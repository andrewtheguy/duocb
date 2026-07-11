//! Minimal config persistence: pre-fills the nostr token-mode forms so a
//! standing pairing's 47-char token and device name don't have to be retyped every
//! launch. The initiator saves before starting; the connector saves only after
//! successful authentication. Clipboard content and the inbox are never persisted.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions, TryLockError};
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
            .join("config.toml"),
    };
    if path.is_absolute() {
        Ok(path)
    } else {
        Ok(std::env::current_dir()
            .context("resolving relative config path")?
            .join(path))
    }
}

fn lock_path(config_path: &Path) -> PathBuf {
    let mut name = config_path.as_os_str().to_os_string();
    name.push(".lock");
    PathBuf::from(name)
}

/// Process-lifetime lock scoped to one config path. The stable sidecar is used
/// instead of the config inode because saving atomically replaces that inode.
pub struct ConfigLock {
    _file: File,
}

/// Acquire exclusive ownership of `config_path` for this process. Different
/// explicit config paths deliberately acquire different locks.
pub fn acquire_lock(config_path: &Path) -> Result<ConfigLock> {
    let path = lock_path(config_path);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating config directory {}", dir.display()))?;
    }
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("opening config lock {}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(ConfigLock { _file: file }),
        Err(TryLockError::WouldBlock) => anyhow::bail!(
            "another duocb instance is already using config {} (use --config <path> for an independent instance)",
            config_path.display()
        ),
        Err(TryLockError::Error(e)) => {
            Err(e).with_context(|| format!("locking config {}", config_path.display()))
        }
    }
}

impl Config {
    /// Load the config, returning defaults when the file is missing or
    /// unreadable (a broken config must never block startup).
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                log::warn!("Ignoring malformed config {}: {e}", path.display());
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self, path: &Path) -> Result<()> {
        let dir = path.parent().expect("config path always has a parent");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating config directory {}", dir.display()))?;
        let content = toml::to_string_pretty(self).context("serializing config")?;

        // Write to a temp file in the same directory, flush, then rename over
        // the destination: a crash mid-write can never leave a truncated
        // config, and same-directory rename replaces atomically.
        let mut tmp_name = path.as_os_str().to_os_string();
        tmp_name.push(".tmp");
        let tmp = PathBuf::from(tmp_name);
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&tmp)
                .with_context(|| format!("creating {}", tmp.display()))?;
            // The token is a credential: keep the file owner-only. Applied
            // before any content is written. (Windows: %APPDATA% is already
            // per-user; no extra ACL is set.)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                file.set_permissions(std::fs::Permissions::from_mode(0o600))
                    .context("restricting config file permissions")?;
            }
            file.write_all(content.as_bytes())
                .with_context(|| format!("writing {}", tmp.display()))?;
            file.sync_all()
                .with_context(|| format!("flushing {}", tmp.display()))?;
        }
        std::fs::rename(&tmp, path)
            .with_context(|| format!("replacing config {}", path.display()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_lock_is_exclusive_per_path() {
        let dir = std::env::temp_dir().join(format!(
            "duocb-config-lock-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first_path = dir.join("mac1.toml");
        let second_path = dir.join("mac2.toml");

        let first = acquire_lock(&first_path).expect("first lock");
        assert!(acquire_lock(&first_path).is_err(), "same config must conflict");
        let _second = acquire_lock(&second_path).expect("different config locks independently");
        drop(first);
        let _again = acquire_lock(&first_path).expect("lock releases on drop");

        let _ = std::fs::remove_dir_all(dir);
    }
}
