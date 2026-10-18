//! The approval dialog (egui, M1). It runs as its own process under a
//! dedicated user, so a native dialog (e.g. SwiftUI on macOS) can replace it
//! without touching the daemon.

/// Protects the password field from other clients while the dialog is up:
/// X11 keyboard grab, nothing on Wayland (the compositor isolates clients),
/// `EnableSecureEventInput` on macOS.
pub trait KeyboardGuard {
    /// Whether the guard is actually in effect. The dialog shows this, so
    /// it must not overstate.
    fn active(&self) -> bool;
}

/// For sessions with no guard available; reports itself as inactive.
pub struct NoGuard;

impl KeyboardGuard for NoGuard {
    fn active(&self) -> bool {
        false
    }
}
