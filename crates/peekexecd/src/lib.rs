//! peekexecd: the root side of peekexec.
//!
//! The daemon logic is written against the traits in [`platform`]; each OS
//! supplies implementations under `platform/<os>/`. Porting means adding a
//! backend directory, not touching the daemon logic.

pub mod exec;
pub mod platform;
pub mod prepare;
pub mod prompt;
pub mod server;
pub mod session;
pub mod trust;
