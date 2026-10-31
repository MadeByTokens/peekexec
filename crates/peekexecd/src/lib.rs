//! peekexecd: the root side of peekexec.
//!
//! The daemon logic is written against the traits in [`platform`]; each OS
//! supplies implementations under `platform/<os>/`. Porting means adding a
//! backend directory, not touching the daemon logic.

// An approver with no human must not exist in an optimized build, whatever
// the packaging does.
#[cfg(all(feature = "test-approver", not(debug_assertions)))]
compile_error!("test-approver is for debug builds and tests only");

pub mod exec;
pub mod inspect;
pub mod platform;
pub mod prepare;
pub mod prompt;
pub mod server;
pub mod session;
pub mod sessions;
pub mod spawn;
pub mod trust;
