//! duocb-core: the portable core of duocb — key auth, wire protocol, nostr
//! signaling, and the headless tokio networking runtime. No GUI, no system
//! clipboard, no config file: those live in the desktop crate (`crates/duocb`).
//!
//! The layers are deliberately separable. [`auth`], [`protocol`], [`key_auth`]
//! and [`card_exchange`] are about *who* two devices are and what they say to
//! each other; a transport only has to carry that conversation. iroh is the
//! transport duocb ships with, not an assumption baked through the crate —
//! [`transport`] states the contract, [`transport::iroh_quic`] is the shipping
//! implementation, and [`transport::dummy`] runs the same session over plain
//! TCP to keep the boundary honest.

// Re-exported so downstream crates can name iroh types without carrying their
// own iroh dependency and risking version skew. It is the current transport's
// vocabulary, not duocb's own — see `transport`.
pub use iroh;

pub mod auth;
pub mod card_exchange;
mod hosting_record;
pub mod identity;
pub mod key_auth;
pub mod lan;
pub mod net;
pub mod nostr;
pub mod pin;
pub mod pin_auth;
mod pin_record;
pub mod protocol;
pub mod subnet;
pub mod transport;
