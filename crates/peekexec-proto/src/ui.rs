//! Daemon ⇄ dialog messages, one JSON object per line over the dialog
//! process's stdin/stdout. The dialog exits when its stdin closes.

use serde::{Deserialize, Serialize};

use crate::view::PromptView;
use crate::wire::wipe;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum ToUi {
    Show {
        view: Box<PromptView>,
    },
    WrongPassword {
        attempts_left: u8,
    },
    /// The desktop's own approval prompt is up; the dialog waits.
    SystemPromptOpen,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "msg", rename_all = "snake_case")]
pub enum FromUi {
    Approve { password: Option<Secret> },
    Cancel,
    Deny { reason: String },
}

/// A password in transit: wiped when dropped, never printed. Every copy
/// the daemon or the dialog makes of one is a `Secret` or a buffer wiped
/// after use ([`crate::wire`] wipes its message buffers).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Secret(String);

impl Secret {
    pub fn new(s: String) -> Secret {
        Secret(s)
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        let mut bytes = std::mem::take(&mut self.0).into_bytes();
        // The whole allocation, not only the current length.
        bytes.resize(bytes.capacity(), 0);
        wipe(&mut bytes);
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(…)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_never_printed() {
        let msg = FromUi::Approve {
            password: Some(Secret::new("hunter2".into())),
        };
        assert!(!format!("{msg:?}").contains("hunter2"));
        // It still travels.
        let json = serde_json::to_string(&msg).unwrap();
        let back: FromUi = serde_json::from_str(&json).unwrap();
        assert_eq!(back, msg);
    }
}
