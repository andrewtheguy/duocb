//! The application identity key's home: the OS credential store.
//!
//! The config file holds only public material — the device suffix, the chosen
//! name, and the signed cards. The `nsec` behind them never touches disk in
//! duocb's own storage; it goes to the Keychain on macOS, the Credential
//! Manager on Windows, and the Secret Service (gnome-keyring, KWallet, …) on
//! Linux, each of which keeps it readable only by the logged-in user and, on
//! macOS and Linux, encrypted while the session is locked.
//!
//! Entries are keyed by the *config path*, not by a fixed account name, because
//! duocb deliberately supports several independent instances on one machine
//! (`--config`, see the E2E notes in AGENTS.md). Each config owns its own
//! identity, so each config owns its own credential.

use anyhow::{Context, Result};

/// Service name every duocb credential is filed under.
const SERVICE: &str = "duocb";

/// Install this platform's credential store as the process default. Must run
/// before any [`Entry`](keyring_core::Entry) is created, so `main` calls it
/// ahead of touching the config.
///
/// There is no file fallback on purpose: silently writing the key back to disk
/// when the credential store is missing would make the identity's protection
/// depend on the environment without anyone noticing.
pub fn init_store() -> Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()
        .context("opening the macOS Keychain")?;
    #[cfg(target_os = "linux")]
    let store = dbus_secret_service_keyring_store::Store::new().context(
        "connecting to the Secret Service on the session bus \
         (is gnome-keyring-daemon or kwalletd running?)",
    )?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()
        .context("opening the Windows Credential Manager")?;

    keyring_core::set_default_store(store);
    Ok(())
}

/// The credential holding the identity key for `account`.
fn entry(account: &str) -> Result<keyring_core::Entry> {
    keyring_core::Entry::new(SERVICE, account)
        .with_context(|| format!("addressing the credential store entry for {account}"))
}

/// Read the stored `nsec` for `account`. `Ok(None)` means no credential exists
/// yet — a first launch — and is distinct from a store that could not be read,
/// which is an error so a locked or broken keyring never looks like a fresh
/// install.
pub fn load_identity(account: &str) -> Result<Option<String>> {
    match entry(account)?.get_password() {
        Ok(secret) => Ok(Some(secret)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading the identity key for {account}")),
    }
}

/// Store `secret` as the identity key for `account`, replacing any previous one.
pub fn save_identity(account: &str, secret: &str) -> Result<()> {
    entry(account)?
        .set_password(secret)
        .with_context(|| format!("storing the identity key for {account}"))
}

/// Point the process at an in-memory store, once per test binary. Config tests
/// round-trip real saves, and they must not write into (or delete from) the
/// developer's own Keychain to do it.
#[cfg(test)]
pub(crate) fn init_mock_store() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        keyring_core::set_default_store(
            keyring_core::mock::Store::new().expect("building the mock credential store"),
        );
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deletes the test credential on unwind, so a failing assertion cannot
    /// leave a stray entry behind in the real credential store.
    struct Cleanup(String);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            // Best-effort and deliberately silent: on the happy path the test
            // has already deleted the entry, so the expected outcome here is a
            // "no such credential" error. Panicking in Drop during an unwind
            // would abort the process and hide the real failure.
            if let Ok(entry) = entry(&self.0) {
                let _ = entry.delete_credential();
            }
        }
    }

    /// Round-trips a throwaway key through the *real* platform store.
    /// `#[ignore]` because it writes to the developer's Keychain / Credential
    /// Manager and, on Linux, needs an unlocked Secret Service session.
    ///
    /// Run it on its own — `cargo test -p duocb -- --ignored live_credential` —
    /// and never under `--include-ignored`: [`init_store`] replaces the
    /// process-wide default store, so sharing a run with the mock-backed config
    /// tests would point their saves at the real credential store.
    #[test]
    #[ignore]
    fn live_credential_store_round_trip() {
        init_store().expect("no native credential store available");
        let account = format!("/tmp/duocb-keychain-test-{}.json", std::process::id());
        let secret = duocb_core::auth::Identity::generate().to_nsec();

        assert_eq!(
            load_identity(&account).expect("read an absent credential"),
            None,
            "the test account must start empty"
        );
        save_identity(&account, &secret).expect("save");
        // Armed the moment the entry exists — every assertion below is now
        // covered whether it passes or panics.
        let _cleanup = Cleanup(account.clone());
        assert_eq!(load_identity(&account).unwrap().as_deref(), Some(&*secret));

        entry(&account)
            .unwrap()
            .delete_credential()
            .expect("cleanup");
        assert_eq!(load_identity(&account).unwrap(), None, "entry should be gone");
    }
}
