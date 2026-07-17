//! Minimal config persistence for the configure mode: the standing secret (the
//! 47-char auth token), this device's short name, and its permanent random
//! suffix. The setup wizard saves the secret and name as soon as they are
//! entered; the suffix is generated on the first launch with this config file
//! and never changes (it survives clearing the secret). The config is
//! per-machine — copying it to another device is not supported. Clipboard
//! content and the inbox are never persisted.
//!
//! The config is a machine-managed JSON file, not meant for hand editing. duocb
//! holds an exclusive OS lock on a sibling `<config>.lock` file for the whole
//! session, which stops a second local instance from claiming the same identity
//! without tying the lock to the config inode. Each save writes and flushes the
//! complete new content to a sibling `<config>.tmp`, then atomically renames it
//! over the config. A crash during a save therefore leaves either the old or new
//! complete JSON file at the configured path, never an in-place torn write.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions, TryLockError};
use std::io::Write as _;
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

/// Process-lifetime exclusive lock on a sibling lock file. Keeping the lock on
/// a stable sidecar inode lets config saves atomically replace the JSON inode.
/// Different explicit config paths deliberately acquire independent locks.
pub struct ConfigLock {
    _lock_file: File,
    path: PathBuf,
}

fn sibling_path(path: &Path, suffix: &str) -> PathBuf {
    let mut name = path.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

/// Open a sibling `<config>.lock` file (creating it and the parent directory if
/// needed) and take an exclusive OS lock on it for this process. Fails if
/// another duocb instance already holds the lock for the same config path.
pub fn acquire_lock(config_path: &Path) -> Result<ConfigLock> {
    if let Some(dir) = config_path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating config directory {}", dir.display()))?;
    }
    let lock_path = sibling_path(config_path, ".lock");
    let lock_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)
        .with_context(|| format!("opening config lock {}", lock_path.display()))?;

    restrict_to_owner(&lock_file)?;

    match lock_file.try_lock() {
        Ok(()) => Ok(ConfigLock {
            _lock_file: lock_file,
            path: config_path.to_path_buf(),
        }),
        Err(TryLockError::WouldBlock) => anyhow::bail!(
            "another duocb instance is already using config {} (use --config <path> for an independent instance)",
            config_path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking config lock {}", lock_path.display()))
        }
    }
}

impl ConfigLock {
    /// The resolved config path, for display.
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn temp_path(&self) -> PathBuf {
        sibling_path(&self.path, ".tmp")
    }

    /// Read the current config path. A missing file is a first launch; any
    /// unreadable or malformed file is an error so startup cannot silently
    /// replace broken persisted state with defaults.
    pub fn load(&self) -> Result<Config> {
        let content = match std::fs::read_to_string(&self.path) {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("reading config {}", self.path.display()));
            }
        };
        serde_json::from_str(&content)
            .with_context(|| format!("parsing config {}", self.path.display()))
    }

    /// Persist the config by flushing complete new content to a sibling temp
    /// file and atomically replacing the config path with it. The stable sibling
    /// lock remains held while the JSON inode changes.
    pub fn save(&self, cfg: &Config) -> Result<()> {
        let content = serde_json::to_string_pretty(cfg).context("serializing config")?;

        let temp = self.temp_path();
        write_private_file(&temp, content.as_bytes())
            .with_context(|| format!("staging config {}", temp.display()))?;
        std::fs::rename(&temp, &self.path).with_context(|| {
            format!(
                "atomically replacing config {} from {}",
                self.path.display(),
                temp.display()
            )
        })?;
        Ok(())
    }
}

/// Restrict a config-related file to owner-only access. Unix-only; a no-op
/// elsewhere (on Windows, `%APPDATA%` is already per-user, so no extra ACL is
/// set).
#[cfg(unix)]
fn restrict_to_owner(file: &File) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
        .context("restricting config-related file permissions")
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
    fn config_lock_is_exclusive_and_separate_from_config() {
        let dir = temp_dir();
        let first_path = dir.join("mac1.json");
        let second_path = dir.join("mac2.json");

        let first = acquire_lock(&first_path).expect("first lock");
        assert!(!first_path.exists(), "locking must not create the config");
        assert!(
            sibling_path(&first_path, ".lock").exists(),
            "locking must use a sidecar file"
        );
        assert!(
            acquire_lock(&first_path).is_err(),
            "same config must conflict"
        );
        let second = acquire_lock(&second_path).expect("different config locks independently");
        drop(first);
        let again = acquire_lock(&first_path).expect("lock releases on drop");
        drop(again);
        drop(second);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_then_load_roundtrips() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        let lock = acquire_lock(&path).expect("lock");

        assert!(
            lock.load().expect("load fresh config").auth_token.is_none(),
            "fresh config is empty"
        );

        lock.save(&Config {
            auth_token: Some("token-value".to_string()),
            my_name: Some("desktop".to_string()),
            device_suffix: Some("a7B2c3D4".to_string()),
        })
        .expect("save");

        let loaded = lock.load().expect("load saved config");
        assert_eq!(loaded.auth_token.as_deref(), Some("token-value"));
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));

        // A shorter replacement must contain exactly the new JSON.
        lock.save(&Config {
            auth_token: Some("t".to_string()),
            my_name: None,
            device_suffix: None,
        })
        .expect("save shorter");
        let loaded = lock.load().expect("load shorter config");
        assert_eq!(loaded.auth_token.as_deref(), Some("t"));
        assert_eq!(loaded.my_name, None);

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn malformed_config_is_an_error() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, b"{ not valid json").unwrap();

        let lock = acquire_lock(&path).expect("lock");
        let error = lock.load().expect_err("malformed config must fail");
        assert!(
            error.to_string().contains(&format!("parsing config {}", path.display())),
            "error should identify the malformed config: {error:#}"
        );

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn empty_config_is_an_error() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        let lock = acquire_lock(&path).expect("lock");
        lock.save(&Config {
            auth_token: Some("secret".to_string()),
            my_name: Some("desktop".to_string()),
            device_suffix: None,
        })
        .expect("save");

        // An empty file is not valid JSON and must not silently reset state.
        std::fs::write(&path, b"").unwrap();
        let error = lock.load().expect_err("empty config must fail");
        assert!(
            error.to_string().contains(&format!("parsing config {}", path.display())),
            "error should identify the empty config: {error:#}"
        );

        drop(lock);
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

        let lock = acquire_lock(&path).expect("lock");
        let loaded = lock.load().expect("load config without suffix");
        assert_eq!(loaded.auth_token.as_deref(), Some("tok"));
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));
        assert_eq!(loaded.device_suffix, None);

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn clearing_the_secret_keeps_the_suffix() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        let lock = acquire_lock(&path).expect("lock");

        lock.save(&Config {
            auth_token: Some("secret".to_string()),
            my_name: Some("desktop".to_string()),
            device_suffix: Some("a7B2c3D4".to_string()),
        })
        .expect("save");

        // The clear-secret action drops the token but must keep the permanent
        // suffix (and may keep the name as a prefill).
        let mut cleared = lock.load().expect("load config to clear");
        cleared.auth_token = None;
        lock.save(&cleared).expect("save cleared");

        let loaded = lock.load().expect("load cleared config");
        assert_eq!(loaded.auth_token, None);
        assert_eq!(loaded.device_suffix.as_deref(), Some("a7B2c3D4"));

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_atomically_replaces_the_config_inode() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        let lock = acquire_lock(&path).expect("lock");
        lock.save(&Config {
            auth_token: Some("old".to_string()),
            my_name: Some("old-name".to_string()),
            device_suffix: None,
        })
        .expect("save old config");
        let old_file = File::open(&path).expect("open old config inode");

        lock.save(&Config {
            auth_token: Some("new".to_string()),
            my_name: Some("new-name".to_string()),
            device_suffix: None,
        })
        .expect("save new config");

        // An open handle still sees the old inode, while the configured path now
        // resolves to the complete replacement. This distinguishes rename from
        // an in-place overwrite.
        let old: Config = serde_json::from_reader(old_file).expect("parse old inode");
        assert_eq!(old.auth_token.as_deref(), Some("old"));
        assert_eq!(old.my_name.as_deref(), Some("old-name"));

        let current = lock.load().expect("load current config");
        assert_eq!(current.auth_token.as_deref(), Some("new"));
        assert_eq!(current.my_name.as_deref(), Some("new-name"));
        assert!(!sibling_path(&path, ".tmp").exists());
        assert!(sibling_path(&path, ".lock").exists());

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }
}
