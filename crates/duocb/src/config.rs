//! Strict, local-first configure-mode persistence.
//!
//! Persisted state is split by sensitivity. The application identity key lives
//! in the OS credential store (see [`crate::keychain`]); the JSON file below
//! holds only the public remainder — device suffix, chosen name, and the signed
//! cards. Both halves are keyed by the same config path, so the `--config`
//! instances used for same-machine E2E runs stay fully independent.
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

/// Bumped to 5 with the move of the identity key into the OS credential store:
/// a version-4 config still carries `identity_secret`, which `deny_unknown_fields`
/// now rejects. Failing the version check up front beats a confusing field error.
pub const CONFIG_VERSION: u32 = 5;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    /// Persistent application identity, encoded as NIP-19 `nsec`. Skipped by
    /// serde in both directions: [`ConfigLock::load`] fills it from the OS
    /// credential store and [`ConfigLock::save`] writes it back there, so the
    /// key is never part of the JSON on disk.
    #[serde(skip)]
    pub identity_secret: String,
    /// Permanent random suffix appended to the user-chosen short name.
    pub device_suffix: String,
    pub my_name: Option<String>,
    pub self_card: Option<String>,
    #[serde(default)]
    pub peers: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            identity_secret: duocb_core::auth::Identity::generate().to_nsec(),
            device_suffix: duocb_core::identity::generate_suffix(),
            my_name: None,
            self_card: None,
            peers: Vec::new(),
        }
    }
}

impl std::fmt::Debug for Config {
    /// Manual impl so the secret can never leak through debug logging.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("version", &self.version)
            .field("identity_secret", &"***")
            .field("device_suffix", &self.device_suffix)
            .field("my_name", &self.my_name)
            .field("self_card", &self.self_card.as_ref().map(|_| "<signed card>"))
            .field("peers", &self.peers.len())
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

    /// Credential-store account for this instance's identity key. The config
    /// path is the natural key: it is what makes two `--config` instances
    /// distinct in every other respect too.
    fn account(&self) -> String {
        self.path.display().to_string()
    }

    fn temp_path(&self) -> PathBuf {
        sibling_path(&self.path, ".tmp")
    }

    /// Read the current config path, pairing it with the identity key held in
    /// the OS credential store. A missing file is a first launch; any
    /// unreadable or malformed file is an error so startup cannot silently
    /// replace broken persisted state with defaults.
    pub fn load(&self) -> Result<Config> {
        let content = match std::fs::read_to_string(&self.path) {
            // No config file means no identity yet: mint one, and leave the
            // credential store alone until something is actually saved. Any
            // credential left over from a deleted config is replaced then.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Config::default()),
            Ok(content) => content,
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("reading config {}", self.path.display()));
            }
        };
        let mut config: Config = serde_json::from_str(&content)
            .with_context(|| format!("parsing config {}", self.path.display()))?;
        if config.version != CONFIG_VERSION {
            anyhow::bail!(
                "config {} has unsupported version {} (this release does not migrate older configs)",
                self.path.display(),
                config.version
            );
        }
        // A saved config always had its key written to the credential store
        // first, so a missing credential here is real loss — a config copied
        // from another machine or user, or an emptied keyring — not a first
        // launch. Say so rather than silently minting a new identity, which
        // would strand every peer that already trusts the old one.
        config.identity_secret = crate::keychain::load_identity(&self.account())?.with_context(
            || {
                format!(
                    "config {} has no identity key in the OS credential store \
                     (the config and its key are stored separately, and the key does not travel with the file)",
                    self.path.display()
                )
            },
        )?;
        let identity = duocb_core::auth::Identity::parse_nsec(&config.identity_secret)
            .with_context(|| format!("config {} has an invalid identity key", self.path.display()))?;
        if !duocb_core::identity::is_valid_suffix(&config.device_suffix) {
            anyhow::bail!(
                "config {} has an invalid device suffix",
                self.path.display()
            );
        }
        match (&config.my_name, &config.self_card) {
            (None, None) => {}
            (Some(name), Some(encoded)) => {
                duocb_core::identity::validate_name(name).with_context(|| {
                    format!("config {} has an invalid device name", self.path.display())
                })?;
                let card = duocb_core::auth::IdentityCard::parse(encoded).with_context(|| {
                    format!("config {} has an invalid self card", self.path.display())
                })?;
                let display_name =
                    duocb_core::identity::display_identity(name, &config.device_suffix);
                if card.public_key() != identity.public_key() || card.name() != display_name {
                    anyhow::bail!(
                        "config {} self card does not match its identity and name",
                        self.path.display()
                    );
                }
            }
            _ => anyhow::bail!(
                "config {} must contain both my_name and self_card, or neither",
                self.path.display()
            ),
        }
        if config.peers.len() > duocb_core::auth::MAX_TRUSTED_PEERS {
            anyhow::bail!(
                "config {} has more than {} trusted peers",
                self.path.display(),
                duocb_core::auth::MAX_TRUSTED_PEERS
            );
        }
        let mut seen = std::collections::HashSet::new();
        for encoded in &config.peers {
            let card = duocb_core::auth::IdentityCard::parse(encoded).with_context(|| {
                format!("config {} has an invalid peer card", self.path.display())
            })?;
            if card.public_key() == identity.public_key() {
                anyhow::bail!("config {} peer list contains itself", self.path.display());
            }
            if !seen.insert(card.public_key()) {
                anyhow::bail!(
                    "config {} peer list contains a duplicate public key",
                    self.path.display()
                );
            }
        }
        Ok(config)
    }

    /// Persist the config: the identity key to the OS credential store, then
    /// the public remainder by flushing complete new content to a sibling temp
    /// file and atomically replacing the config path with it. The stable sibling
    /// lock remains held while the JSON inode changes.
    ///
    /// The credential goes first so the two can only ever fall out of step in
    /// the recoverable direction — a key with no config reads as a first
    /// launch, whereas a config with no key is a hard startup error.
    pub fn save(&self, cfg: &Config) -> Result<()> {
        crate::keychain::save_identity(&self.account(), &cfg.identity_secret)?;

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
/// disk. The identity key lives in the credential store rather than here, but
/// the trusted-peer list is still nobody else's business; permissions are set
/// while the file is still empty so it is never briefly group/world-readable.
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

    /// A directory unique to each caller, plus the per-process test setup every
    /// case here needs. Tests run in parallel and each cleans up its own
    /// directory, so a process-wide atomic counter (not a timestamp, which can
    /// collide within the same nanosecond) keeps them isolated; the mock
    /// credential store keeps their saves out of the developer's real keyring.
    fn temp_dir() -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};

        crate::keychain::init_mock_store();
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "duocb-config-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn configured(name: &str) -> Config {
        let identity = duocb_core::auth::Identity::generate();
        let suffix = "a7B2c3D4";
        let card = identity.card(name, suffix).unwrap();
        Config {
            version: CONFIG_VERSION,
            identity_secret: identity.to_nsec(),
            device_suffix: suffix.to_string(),
            my_name: Some(name.to_string()),
            self_card: Some(card.encode()),
            peers: Vec::new(),
        }
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

        let fresh = lock.load().expect("load fresh config");
        assert!(duocb_core::auth::Identity::parse_nsec(&fresh.identity_secret).is_ok());
        assert!(duocb_core::identity::is_valid_suffix(
            &fresh.device_suffix
        ));
        assert!(fresh.self_card.is_none());

        let saved = configured("desktop");
        let public_key = duocb_core::auth::Identity::parse_nsec(&saved.identity_secret)
            .unwrap()
            .public_key();
        lock.save(&saved).expect("save");

        let loaded = lock.load().expect("load saved config");
        assert_eq!(loaded.my_name.as_deref(), Some("desktop"));
        assert_eq!(
            duocb_core::auth::Identity::parse_nsec(&loaded.identity_secret)
                .unwrap()
                .public_key(),
            public_key
        );

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Trust that has aged out must still load. Card parsing is deliberately
    /// clock-free so an expired peer stays visible and removable instead of
    /// making the whole config unloadable on the day it lapses.
    #[test]
    fn an_expired_peer_card_still_loads() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        let lock = acquire_lock(&path).expect("lock");

        let stale = duocb_core::auth::Identity::generate()
            .card_valid_from(
                "laptop",
                "x9Y8z7W6",
                duocb_core::auth::unix_now() - duocb_core::auth::CARD_TTL_SECS - 1,
            )
            .unwrap();
        assert!(stale.is_expired());
        let mut saved = configured("desktop");
        saved.peers = vec![stale.encode()];
        lock.save(&saved).expect("save");

        let loaded = lock.load().expect("an expired peer must not break the load");
        assert_eq!(loaded.peers.len(), 1);
        assert!(
            duocb_core::auth::IdentityCard::parse(&loaded.peers[0])
                .unwrap()
                .is_expired()
        );

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
        lock.save(&configured("desktop")).expect("save");

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
    fn shared_secret_config_is_not_migrated() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, br#"{ "secret": "sec", "my_name": "desktop" }"#).unwrap();

        let lock = acquire_lock(&path).expect("lock");
        let error = lock.load().expect_err("legacy configs must be rejected");
        assert!(
            error
                .to_string()
                .contains(&format!("parsing config {}", path.display())),
            "error should identify the invalid config: {error:#}"
        );

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A config from before the key moved out of the file. `deny_unknown_fields`
    /// rejects the now-skipped `identity_secret`, so it never loads and its
    /// plaintext key is never adopted.
    #[test]
    fn in_file_key_config_is_not_migrated() {
        let dir = temp_dir();
        let path = dir.join("config.json");
        let identity = duocb_core::auth::Identity::generate();
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            &path,
            format!(
                r#"{{"version":4,"identity_secret":"{}","device_suffix":"a7B2c3D4","my_name":null,"self_card":null,"peers":[]}}"#,
                identity.to_nsec()
            ),
        )
        .unwrap();

        let lock = acquire_lock(&path).expect("lock");
        let error = lock
            .load()
            .expect_err("configs carrying the key in the file must be rejected");
        assert!(
            error
                .to_string()
                .contains(&format!("parsing config {}", path.display()))
        );

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// The whole point of the split: the key must not be recoverable from the
    /// file, and the file must still describe the same identity after a reload.
    #[test]
    fn the_identity_key_never_reaches_the_config_file() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        let lock = acquire_lock(&path).expect("lock");
        let saved = configured("desktop");
        let nsec = saved.identity_secret.clone();
        lock.save(&saved).expect("save");

        let on_disk = std::fs::read_to_string(&path).expect("read config");
        assert!(
            !on_disk.contains(&nsec) && !on_disk.contains("identity_secret"),
            "the config file must carry neither the key nor a field for it: {on_disk}"
        );
        assert_eq!(
            crate::keychain::load_identity(&path.display().to_string()).unwrap(),
            Some(nsec.clone()),
            "the key belongs in the credential store"
        );
        assert_eq!(lock.load().expect("load").identity_secret, nsec);

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// Two `--config` instances on one machine each own an identity, so they
    /// must not share one credential.
    #[test]
    fn each_config_path_owns_its_own_credential() {
        let dir = temp_dir();
        let (first_path, second_path) = (dir.join("peer1.json"), dir.join("peer2.json"));

        let first = acquire_lock(&first_path).expect("first lock");
        let second = acquire_lock(&second_path).expect("second lock");
        first.save(&configured("peer-one")).expect("save first");
        second.save(&configured("peer-two")).expect("save second");

        assert_ne!(
            first.load().unwrap().identity_secret,
            second.load().unwrap().identity_secret
        );

        drop(first);
        drop(second);
        let _ = std::fs::remove_dir_all(dir);
    }

    /// A config file that arrived without its credential — copied from another
    /// machine or user, or left behind by an emptied keyring — must fail loudly
    /// instead of quietly minting a new identity nobody trusts.
    #[test]
    fn a_config_without_its_credential_is_an_error() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        let lock = acquire_lock(&path).expect("lock");
        lock.save(&configured("desktop")).expect("save");
        keyring_core::Entry::new("duocb", &path.display().to_string())
            .expect("entry")
            .delete_credential()
            .expect("drop the credential");

        let error = lock.load().expect_err("a keyless config must fail");
        assert!(
            error
                .to_string()
                .contains("has no identity key in the OS credential store"),
            "error should name the missing credential: {error:#}"
        );

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn save_atomically_replaces_the_config_inode() {
        let dir = temp_dir();
        let path = dir.join("config.json");

        let lock = acquire_lock(&path).expect("lock");
        lock.save(&configured("old-name")).expect("save old config");
        let old_file = File::open(&path).expect("open old config inode");

        lock.save(&configured("new-name")).expect("save new config");

        // An open handle still sees the old inode, while the configured path now
        // resolves to the complete replacement. This distinguishes rename from
        // an in-place overwrite.
        let old: Config = serde_json::from_reader(old_file).expect("parse old inode");
        assert_eq!(old.my_name.as_deref(), Some("old-name"));

        let current = lock.load().expect("load current config");
        assert_eq!(current.my_name.as_deref(), Some("new-name"));
        assert!(!sibling_path(&path, ".tmp").exists());
        assert!(sibling_path(&path, ".lock").exists());

        drop(lock);
        let _ = std::fs::remove_dir_all(dir);
    }
}
