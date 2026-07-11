//! Minimal config persistence: pre-fills the nostr token-mode forms so a
//! standing pairing's 47-char token and names don't have to be retyped every
//! launch. Written only via the explicit "Remember" button — never
//! automatically. Clipboard content and the inbox are never persisted.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Shared auth token for the nostr token/name mode.
    pub auth_token: Option<String>,
    /// This device's name (server side of token mode).
    pub my_name: Option<String>,
    /// The other device's name (client side of token mode).
    pub peer_name: Option<String>,
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
        std::fs::write(&path, content)
            .with_context(|| format!("writing config {}", path.display()))?;
        Ok(())
    }
}
