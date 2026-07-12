//! duocb-core: the portable core of duocb — token auth, wire protocol, nostr
//! signaling, and the headless tokio networking runtime. No GUI, no system
//! clipboard, no config file: those live in the desktop crate (`crates/duocb`)
//! and, on iOS, on the Swift side of the FFI (`crates/duocb-ffi`).

// Re-exported so downstream crates can name iroh types without carrying their
// own iroh dependency and risking version skew.
pub use iroh;

pub mod auth;
pub mod net;
pub mod nostr;
pub mod pin;
pub mod pin_auth;
pub mod protocol;
