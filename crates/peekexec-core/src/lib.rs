//! Platform-neutral core of peekexec: what a request is, how it is hashed,
//! and the text checks that run before anything is shown to the human.
//!
//! Nothing in this crate may touch the OS. That is what keeps the macOS port
//! a matter of adding platform backends in `peekexecd`.

pub mod display;
pub mod request;
pub mod textcheck;

pub use request::{Action, Request};
