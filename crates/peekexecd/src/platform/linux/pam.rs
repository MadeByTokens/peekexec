//! Minimal Linux-PAM binding: start, authenticate, check the account, end.
//! Linked against `libpam.so.0` directly (see build.rs), so building needs
//! no PAM headers and no bindgen.

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_void};

use crate::platform::{Authenticator, PlatformError};

const PAM_SUCCESS: c_int = 0;
const PAM_BUF_ERR: c_int = 5;
const PAM_CONV_ERR: c_int = 19;
const PAM_PROMPT_ECHO_OFF: c_int = 1;
const PAM_PROMPT_ECHO_ON: c_int = 2;
const PAM_DISALLOW_NULL_AUTHTOK: c_int = 0x1;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn = extern "C" fn(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int;

#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

#[repr(C)]
struct PamHandle {
    _private: [u8; 0],
}

extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        pamh: *mut *mut PamHandle,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_acct_mgmt(pamh: *mut PamHandle, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut PamHandle, status: c_int) -> c_int;
    fn pam_strerror(pamh: *mut PamHandle, errnum: c_int) -> *const c_char;
}

/// What the conversation may answer with.
struct Answers {
    user: CString,
    password: Option<CString>,
    /// The password is handed out once per attempt; a second hidden prompt
    /// (e.g. an OTP) cannot be answered from the dialog yet.
    password_used: bool,
}

extern "C" fn conversation(
    num_msg: c_int,
    msg: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    appdata: *mut c_void,
) -> c_int {
    if num_msg <= 0 || msg.is_null() || resp.is_null() || appdata.is_null() {
        return PAM_CONV_ERR;
    }
    let n = num_msg as usize;
    // SAFETY: PAM frees this array (and each `resp`) with free(), so it
    // must come from calloc; calloc zeroes it, so unused slots stay null.
    let replies =
        unsafe { libc::calloc(n, std::mem::size_of::<PamResponse>()) as *mut PamResponse };
    if replies.is_null() {
        return PAM_BUF_ERR;
    }
    // SAFETY: appdata is the &mut Answers we passed to pam_start, alive
    // for the duration of the PAM call that invoked us.
    let answers = unsafe { &mut *(appdata as *mut Answers) };
    for i in 0..n {
        // SAFETY: Linux-PAM passes an array of `n` message pointers.
        let m = unsafe { &**msg.add(i) };
        let reply: Option<&CStr> = match m.msg_style {
            PAM_PROMPT_ECHO_OFF if !answers.password_used => {
                answers.password_used = true;
                answers.password.as_deref()
            }
            PAM_PROMPT_ECHO_ON => Some(answers.user.as_c_str()),
            PAM_PROMPT_ECHO_OFF => None,
            // Error and info messages need no reply.
            _ => continue,
        };
        let Some(text) = reply else {
            free_replies(replies, n);
            return PAM_CONV_ERR;
        };
        // SAFETY: strdup copies a valid C string; PAM frees it.
        let dup = unsafe { libc::strdup(text.as_ptr()) };
        if dup.is_null() {
            free_replies(replies, n);
            return PAM_BUF_ERR;
        }
        // SAFETY: i < n, within the calloc'd array.
        unsafe { (*replies.add(i)).resp = dup };
    }
    // SAFETY: resp is a valid out-pointer supplied by PAM.
    unsafe { *resp = replies };
    PAM_SUCCESS
}

fn free_replies(replies: *mut PamResponse, n: usize) {
    for i in 0..n {
        // SAFETY: every slot is either null or a strdup'd string.
        unsafe {
            let r = (*replies.add(i)).resp;
            if !r.is_null() {
                // Scrub the password copy before freeing it.
                libc::memset(r.cast(), 0, libc::strlen(r));
                libc::free(r.cast());
            }
        }
    }
    // SAFETY: allocated by calloc above.
    unsafe { libc::free(replies.cast()) };
}

pub struct Pam {
    service: CString,
}

impl Pam {
    pub fn new(service: &str) -> Self {
        Pam {
            service: CString::new(service).expect("service name has no NUL"),
        }
    }
}

fn pam_error(pamh: *mut PamHandle, rc: c_int) -> String {
    // SAFETY: pam_strerror returns a static string for any code.
    let s = unsafe { pam_strerror(pamh, rc) };
    if s.is_null() {
        format!("PAM error {rc}")
    } else {
        // SAFETY: non-null, NUL-terminated static string.
        unsafe { CStr::from_ptr(s) }.to_string_lossy().into_owned()
    }
}

impl Authenticator for Pam {
    fn wants_password(&self) -> bool {
        true
    }

    fn verify(&self, user: &str, password: Option<&str>) -> Result<bool, PlatformError> {
        let to_c = |s: &str| {
            CString::new(s).map_err(|_| PlatformError::Other("NUL byte in credentials".into()))
        };
        let mut answers = Answers {
            user: to_c(user)?,
            password: password.map(to_c).transpose()?,
            password_used: false,
        };
        let conv = PamConv {
            conv: conversation,
            appdata_ptr: (&mut answers as *mut Answers).cast(),
        };
        let mut pamh: *mut PamHandle = std::ptr::null_mut();
        // SAFETY: all pointers are valid for the call; `conv` and `answers`
        // outlive the handle, which is ended below on every path.
        let rc = unsafe {
            pam_start(
                self.service.as_ptr(),
                answers.user.as_ptr(),
                &conv,
                &mut pamh,
            )
        };
        if rc != PAM_SUCCESS {
            return Err(PlatformError::Other(format!(
                "pam_start: {}",
                pam_error(pamh, rc)
            )));
        }
        // SAFETY: pamh is a live handle from pam_start.
        let mut rc = unsafe { pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK) };
        if rc == PAM_SUCCESS {
            // SAFETY: as above.
            rc = unsafe { pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK) };
        }
        // SAFETY: as above; the handle is not used afterwards.
        unsafe { pam_end(pamh, rc) };
        Ok(rc == PAM_SUCCESS)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // These talk to the machine's real PAM stack. A failed attempt can count
    // toward pam_faillock lockout, so they only run when asked:
    //   cargo test -p peekexecd -- --ignored pam

    #[test]
    #[ignore = "uses the real PAM stack; may count toward account lockout"]
    fn wrong_password_is_rejected_not_an_error() {
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap()
            .name;
        let pam = Pam::new("other");
        assert!(!pam
            .verify(&user, Some("definitely-not-the-password-Zq9"))
            .unwrap());
    }

    #[test]
    #[ignore = "uses the real PAM stack; may count toward account lockout"]
    fn missing_password_is_rejected() {
        let user = nix::unistd::User::from_uid(nix::unistd::getuid())
            .unwrap()
            .unwrap()
            .name;
        let pam = Pam::new("other");
        assert!(!pam.verify(&user, None).unwrap());
    }
}
