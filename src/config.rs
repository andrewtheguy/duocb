//! Minimal config persistence: pre-fills the nostr token-mode forms so a
//! standing pairing's 47-char token and names don't have to be retyped every
//! launch. Written only via the explicit "Remember" button — never
//! automatically. Clipboard content and the inbox are never persisted.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Shared auth token for the nostr token/name mode.
    pub auth_token: Option<String>,
    /// This device's name (server side of token mode).
    pub my_name: Option<String>,
    /// The other device's name (client side of token mode).
    pub peer_name: Option<String>,
}

impl std::fmt::Debug for Config {
    /// Manual impl so the auth token can never leak through debug logging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("auth_token", &self.auth_token.as_ref().map(|_| "***"))
            .field("my_name", &self.my_name)
            .field("peer_name", &self.peer_name)
            .finish()
    }
}

fn config_path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("duocb").join("config.toml"))
}

impl Config {
    /// Load the config, returning defaults when the file is missing or
    /// unreadable (a broken config must never block startup).
    pub fn load() -> Self {
        let Some(path) = config_path() else {
            return Self::default();
        };
        match std::fs::read_to_string(&path) {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|e| {
                log::warn!("Ignoring malformed config {}: {e}", path.display());
                Self::default()
            }),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path().context("no config directory on this platform")?;
        let dir = path.parent().expect("config path always has a parent");
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating config directory {}", dir.display()))?;
        let content = toml::to_string_pretty(self).context("serializing config")?;

        // Write to a temp file in the same directory, flush, then rename over
        // the destination: a crash mid-write can never leave a truncated
        // config, and same-directory rename replaces atomically.
        let tmp = path.with_extension("toml.tmp");
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
        std::fs::rename(&tmp, &path)
            .with_context(|| format!("replacing config {}", path.display()))?;
        Ok(())
    }
}
