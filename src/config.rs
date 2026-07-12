//! Minimal config persistence: pre-fills the nostr token-mode forms so a
//! standing pairing's 47-char token and device name don't have to be retyped every
//! launch. The initiator saves before starting; the connector saves only after
//! successful authentication. Clipboard content and the inbox are never persisted.
//!
//! The config is a machine-managed JSON file, not meant for hand editing. duocb
//! holds an exclusive OS lock on the file itself for the whole session, which
//! both stops a second local instance from claiming the same identity and guards
//! the file against accidental external edits while duocb runs. Because the lock
//! lives on the file, writes go in place through the held handle rather than via
//! an atomic temp-and-rename (a rename would swap the inode and drop the lock).
//! To keep the crash safety a rename would have given, each save first writes the
//! complete new content to a sibling `<config>.bak`, flushes it, and only then
//! overwrites the config in place; a crash mid-overwrite leaves the config torn
//! but the backup intact, and [`ConfigLock::load`] recovers from it.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Shared auth token for the nostr token/name mode.
    pub auth_token: Option<String>,
    /// This device's unique name in token mode, regardless of whether it starts
    /// or joins the connection.
    pub my_name: Option<String>,
}

impl std::fmt::Debug for Config {
    /// Manual impl so the auth token can never leak through debug logging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("auth_token", &self.auth_token.as_ref().map(|_| "***"))
            .field("my_name", &self.my_name)
            .finish()
    }
}

/// Resolve the config used by this process. An explicit path is intended for
/// same-machine E2E runs; otherwise the normal per-user location is used.
pub fn resolve_path(explicit: Option<PathBuf>) -> Result<PathBuf> {
    let path = match explicit {
        Some(path) => path,
        None => dirs::config_dir()
            .context("no config directory on this platform")?
            .join("duocb")
            .join("config.json"),
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("resolving relative config path")?
            .join(path))
    }
}

/// Process-lifetime exclusive lock on the config file, opened once and held open
/// for the whole session. All config reads and writes go through this handle, so
/// the lock also serves as the sole gateway to the file. Different explicit
/// config paths deliberately acquire independent locks.
pub struct ConfigLock {
    file: File,
    path: PathBuf,
}

/// Open `config_path` (creating it and its parent directory if needed) and take
/// an exclusive OS lock on it for this process. Fails if another duocb instance
/// already holds the lock on the same file.
pub fn acquire_lock(config_path: &Path) -> Result<ConfigLock> {
    if let Some(dir) = config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating config directory {}", dir.display()))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(config_path)
        .with_context(|| format!("opening config {}", config_path.display()))?;

    // The token is a credential: keep the file owner-only. Safe to apply here
    // because the file is still empty (or being reused) before any write.
    restrict_to_owner(&file)?;

    match file.try_lock() {
        Ok(()) => Ok(ConfigLock {
            file,
            path: config_path.to_path_buf(),
        }),
        Err(TryLockError::WouldBlock) => anyhow::bail!(
            "another duocb instance is already using config {} (use --config <path> for an independent instance)",
            config_path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking config {}", config_path.display()))
        }
    }
}

impl ConfigLock {
    /// The resolved config path, for display.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn backup_path(&self) -> PathBuf {
        let mut name = self.path.as_os_str().to_os_string();
        name.push(".bak");
        PathBuf::from(name)
    }

    /// Read the config, returning defaults when nothing valid is on disk (a
    /// broken config must never block startup). Reads the locked file first;
    /// if it is torn — e.g. a crash during an in-place overwrite — falls back to
    /// the sibling backup that [`save`](Self::save) writes before overwriting.
    pub fn load(&mut self) -> Config {
        if let Some(cfg) = self.read_locked() {
            return cfg;
        }
        let backup = self.backup_path();
        match std::fs::read_to_string(&backup) {
            Ok(content) if !content.trim().is_empty() => match serde_json::from_str(&content) {
                Ok(cfg) => {
                    log::warn!("Recovered config from backup {}", backup.display());
                    cfg
                }
                Err(e) => {
                    log::warn!("Ignoring malformed config backup {}: {e}", backup.display());
                    Config::default()
                }
            },
            _ => Config::default(),
        }
    }

    /// Parse the locked config file. `None` means "nothing usable here, try the
    /// backup": the file is empty (a fresh install), unreadable, or malformed.
    fn read_locked(&mut self) -> Option<Config> {
        let mut content = String::new();
        if let Err(e) = self
            .file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.read_to_string(&mut content))
        {
            log::warn!("Ignoring unreadable config {}: {e}", self.path.display());
            return None;
        }
        if content.trim().is_empty() {
            return None;
        }
        match serde_json::from_str(&content) {
            Ok(cfg) => Some(cfg),
            Err(e) => {
                log::warn!("Ignoring malformed config {}: {e}", self.path.display());
                None
            }
        }
    }

    /// Persist the config. The lock stays on the config inode, so this cannot use
    /// an atomic temp-and-rename; instead it writes the complete new content to a
    /// flushed sibling backup first, then overwrites the config in place through
    /// the held handle. A crash before the overwrite finishes leaves the config
    /// torn but the backup whole, and [`load`](Self::load) recovers from it.
    pub fn save(&mut self, cfg: &Config) -> Result<()> {
        let content = serde_json::to_string_pretty(cfg).context("serializing config")?;

        let backup = self.backup_path();
        write_private_file(&backup, content.as_bytes())
            .with_context(|| format!("writing config backup {}", backup.display()))?;

        self.file
            .seek(SeekFrom::Start(0))
            .context("rewinding config for write")?;
        self.file
            .write_all(content.as_bytes())
            .with_context(|| format!("writing config {}", self.path.display()))?;
        // Trim any bytes left over from a previously longer config.
        self.file
            .set_len(content.len() as u64)
            .with_context(|| format!("truncating config {}", self.path.display()))?;
        self.file
            .sync_all()
            .with_context(|| format!("flushing config {}", self.path.display()))?;
        Ok(())
    }
}

/// Restrict `file` to owner-only access, since the config holds a credential.
/// Unix-only; a no-op elsewhere (on Windows, `%APPDATA%` is already per-user, so
/// no extra ACL is set).
#[cfg(unix)]
fn restrict_to_owner(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("restricting config file permissions")
}

#[cfg(not(unix))]
fn restrict_to_owner(_file: &File) -> Result<()> {
    Ok(())
}

/// Truncate-write `bytes` to `path` (creating it), owner-only and flushed to
/// disk. Permissions are set while the file is still empty so the credential it
/// will hold is never briefly group/world-readable.
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    restrict_to_owner(&file)?;
    file.write_all(bytes)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("flushing {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir() -> PathBuf {
        std::env::temp_dir().join(format!(
            "duocb-config-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn config_lock_is_exclusive_per_path() {
        let dir = temp_dir();
        let first_path = dir.join("mac1.json");
        let second_path = dir.join("mac2.json");

        let first = acquire_lock(&first_path).expect("first lock");
        assert!(
            acquire_lock(&first_path).is_err(),
            "same config must conflict"
        );
        let _second = acquire_lock(&second_path).expect("different config locks independently");
        drop(first);
        let _again = acquire_lock(&first_path).expect("lock releases on drop");

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        let mut lock = acquire_lock(&path).expect("lock");

        assert!(lock.load().auth_token.is_none(), "fresh config is empty");

        lock.save(&Config {
            auth_token: Some("token-value".to_string()),
            my_name: Some("desktop".to_string()),
        })
        .expect("save");

        let loaded = lock.load();
        assert_eq!(loaded.auth_token.as_deref(), Some("token-value"));
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));

        // A shorter follow-up write must not leave trailing bytes behind.
        lock.save(&Config {
            auth_token: Some("t".to_string()),
            my_name: None,
        })
        .expect("save shorter");
        let loaded = lock.load();
        assert_eq!(loaded.auth_token.as_deref(), Some("t"));
        assert_eq!(loaded.my_name, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_config_falls_back_to_defaults() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{ not valid json").unwrap();

        let mut lock = acquire_lock(&path).expect("lock");
        let loaded = lock.load();
        assert!(loaded.auth_token.is_none());
        assert!(loaded.my_name.is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn load_recovers_from_backup_when_config_is_torn() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        let mut lock = acquire_lock(&path).expect("lock");
        lock.save(&Config {
            auth_token: Some("good".to_string()),
            my_name: Some("desktop".to_string()),
        })
        .expect("save");
        drop(lock);

        // Simulate a crash during the in-place overwrite: the config is torn but
        // the backup written beforehand is intact.
        std::fs::write(&path, b"{ torn").unwrap();

        let mut lock = acquire_lock(&path).expect("relock");
        let loaded = lock.load();
        assert_eq!(loaded.auth_token.as_deref(), Some("good"));
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));

        let _ = std::fs::remove_dir_all(dir);
    }
}
