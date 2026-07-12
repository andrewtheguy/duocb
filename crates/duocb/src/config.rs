//! Minimal config persistence for the configure mode: the standing secret (the
//! 47-char auth token), this device's short name, and its permanent random
//! suffix. The setup wizard saves the secret and name as soon as they are
//! entered; the suffix is generated on the first launch with this config file
//! and never changes (it survives clearing the secret). The config is
//! per-machine — copying it to another device is not supported. Clipboard
//! content and the inbox are never persisted.
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
    /// The standing secret shared by all of this user's devices (configure mode).
    pub auth_token: Option<String>,
    /// This device's user-chosen short name (without the suffix).
    pub my_name: Option<String>,
    /// Permanent per-device random suffix (8 unambiguous chars), generated on
    /// the first launch with this config file and never regenerated — it
    /// survives clearing the secret, so the device keeps its identity.
    pub device_suffix: Option<String>,
}

impl std::fmt::Debug for Config {
    /// Manual impl so the auth token can never leak through debug logging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("auth_token", &self.auth_token.as_ref().map(|_| "***"))
            .field("my_name", &self.my_name)
            .field("device_suffix", &self.device_suffix)
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

/// What the locked config file held on read (see [`ConfigLock::read_locked`]).
enum LockedConfig {
    Valid(Config),
    /// Empty file: fresh install or deliberate reset — load defaults, do not
    /// consult the backup.
    Empty,
    /// Non-empty malformed or unreadable content (e.g. torn by a crash during
    /// the in-place overwrite) — the backup may recover it.
    Damaged,
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
    /// broken config must never block startup). Reads the locked file first.
    /// An **empty** file is a fresh install or a deliberate reset and yields
    /// defaults immediately — it must never pull stale credentials back from
    /// the backup. Only **non-empty damaged** content (torn by a crash during
    /// the in-place overwrite, or unreadable) falls back to the sibling backup
    /// that [`save`](Self::save) writes before overwriting.
    pub fn load(&mut self) -> Config {
        match self.read_locked() {
            LockedConfig::Valid(cfg) => cfg,
            LockedConfig::Empty => Config::default(),
            LockedConfig::Damaged => {
                let backup = self.backup_path();
                match std::fs::read_to_string(&backup) {
                    Ok(content) if !content.trim().is_empty() => {
                        match serde_json::from_str(&content) {
                            Ok(cfg) => {
                                log::warn!("Recovered config from backup {}", backup.display());
                                cfg
                            }
                            Err(e) => {
                                log::warn!(
                                    "Ignoring malformed config backup {}: {e}",
                                    backup.display()
                                );
                                Config::default()
                            }
                        }
                    }
                    _ => Config::default(),
                }
            }
        }
    }

    /// Parse the locked config file, distinguishing "nothing here" from "torn":
    /// an empty file must load as defaults, while non-empty malformed or
    /// unreadable content is a candidate for backup recovery.
    fn read_locked(&mut self) -> LockedConfig {
        let mut content = String::new();
        if let Err(e) = self
            .file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.read_to_string(&mut content))
        {
            log::warn!("Ignoring unreadable config {}: {e}", self.path.display());
            return LockedConfig::Damaged;
        }
        if content.trim().is_empty() {
            return LockedConfig::Empty;
        }
        match serde_json::from_str(&content) {
            Ok(cfg) => LockedConfig::Valid(cfg),
            Err(e) => {
                log::warn!("Ignoring malformed config {}: {e}", self.path.display());
                LockedConfig::Damaged
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

    /// A directory unique to each caller. Tests run in parallel and each cleans
    /// up its own directory, so a process-wide atomic counter (not a timestamp,
    /// which can collide within the same nanosecond) keeps them isolated.
    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "duocb-config-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
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
            device_suffix: Some("a7B2c3D4".to_string()),
        })
        .expect("save");

        let loaded = lock.load();
        assert_eq!(loaded.auth_token.as_deref(), Some("token-value"));
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));

        // A shorter follow-up write must not leave trailing bytes behind.
        lock.save(&Config {
            auth_token: Some("t".to_string()),
            my_name: None,
            device_suffix: None,
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
    fn emptied_config_loads_defaults_and_ignores_stale_backup() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        // A save leaves a backup with credentials behind.
        let mut lock = acquire_lock(&path).expect("lock");
        lock.save(&Config {
            auth_token: Some("stale".to_string()),
            my_name: Some("desktop".to_string()),
            device_suffix: None,
        })
        .expect("save");
        drop(lock);

        // The user resets/deletes the config (empty file): the stale backup
        // must NOT be restored.
        std::fs::write(&path, b"").unwrap();
        let mut lock = acquire_lock(&path).expect("relock");
        let loaded = lock.load();
        assert!(loaded.auth_token.is_none(), "stale token must not return");
        assert!(loaded.my_name.is_none());

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn config_without_suffix_field_loads_with_none() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        // A config written before the suffix existed: still parses, suffix None,
        // so the app treats it as a first launch for the suffix only.
        std::fs::write(
            &path,
            br#"{ "auth_token": "tok", "my_name": "desktop" }"#,
        )
        .unwrap();

        let mut lock = acquire_lock(&path).expect("lock");
        let loaded = lock.load();
        assert_eq!(loaded.auth_token.as_deref(), Some("tok"));
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));
        assert_eq!(loaded.device_suffix, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clearing_the_secret_keeps_the_suffix() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        let mut lock = acquire_lock(&path).expect("lock");

        lock.save(&Config {
            auth_token: Some("secret".to_string()),
            my_name: Some("desktop".to_string()),
            device_suffix: Some("a7B2c3D4".to_string()),
        })
        .expect("save");

        // The clear-secret action drops the token but must keep the permanent
        // suffix (and may keep the name as a prefill).
        let mut cleared = lock.load();
        cleared.auth_token = None;
        lock.save(&cleared).expect("save cleared");

        let loaded = lock.load();
        assert_eq!(loaded.auth_token, None);
        assert_eq!(loaded.device_suffix.as_deref(), Some("a7B2c3D4"));

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
            device_suffix: None,
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
