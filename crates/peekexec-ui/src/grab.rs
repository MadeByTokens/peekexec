//! X11 keyboard grab while the dialog is open (as pinentry does): other X
//! clients stop receiving key events, so ordinary keyloggers and windows
//! behind the dialog do not see the password. X11 cannot fully isolate a
//! window (e.g. XQueryKeymap polling still works); THREAT_MODEL.md tier 1.
//! On Wayland the compositor already isolates clients, so nothing is done.

use raw_window_handle::{HasDisplayHandle, HasWindowHandle, RawDisplayHandle, RawWindowHandle};
use x11_dl::xlib;

pub struct KeyboardGrab {
    xlib: Option<xlib::Xlib>,
    pub grabbed: bool,
    attempts: u32,
}

/// The window must be viewable before X accepts the grab; retry this many
/// frames, then give up and say so in the dialog.
const MAX_ATTEMPTS: u32 = 120;

impl KeyboardGrab {
    pub fn new() -> Self {
        KeyboardGrab {
            xlib: None,
            grabbed: false,
            attempts: 0,
        }
    }

    /// Call once per frame until it reports success.
    pub fn poll(&mut self, frame: &eframe::Frame) {
        if self.grabbed || self.attempts >= MAX_ATTEMPTS {
            return;
        }
        self.attempts += 1;
        let Some(window) = frame.winit_window() else {
            return;
        };
        let (Ok(dh), Ok(wh)) = (window.display_handle(), window.window_handle()) else {
            return;
        };
        let (RawDisplayHandle::Xlib(d), RawWindowHandle::Xlib(w)) = (dh.as_raw(), wh.as_raw())
        else {
            self.attempts = MAX_ATTEMPTS; // not X11
            return;
        };
        let Some(display) = d.display else {
            return;
        };
        if self.xlib.is_none() {
            self.xlib = xlib::Xlib::open().ok();
        }
        let Some(x) = &self.xlib else {
            self.attempts = MAX_ATTEMPTS;
            return;
        };
        let display = display.as_ptr().cast::<xlib::Display>();
        // SAFETY: `display` and `w.window` are winit's live X connection
        // and window, used on the same (event loop) thread winit uses them.
        let rc = unsafe {
            let rc = (x.XGrabKeyboard)(
                display,
                w.window,
                xlib::True,
                xlib::GrabModeAsync,
                xlib::GrabModeAsync,
                xlib::CurrentTime,
            );
            (x.XFlush)(display);
            rc
        };
        self.grabbed = rc == xlib::GrabSuccess;
    }
}
