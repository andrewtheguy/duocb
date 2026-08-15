//! duocb-core: the portable core of duocb — key auth, wire protocol, nostr
//! signaling, and the headless tokio networking runtime. No GUI, no system
//! clipboard, no config file: those live in the desktop crate (`crates/duocb`).

// Re-exported so downstream crates can name iroh types without carrying their
// own iroh dependency and risking version skew.
pub use iroh;

pub mod auth;
pub mod card_exchange;
pub mod identity;
pub mod lan;
pub mod net;
pub mod nostr;
pub mod pin;
pub mod pin_auth;
mod pin_record;
pub mod protocol;
pub mod subnet;
