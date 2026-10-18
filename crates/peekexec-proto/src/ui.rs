//! Daemon ⇄ dialog messages, one JSON object per line over the dialog
//! process's stdin/stdout. The dialog exits when its stdin closes.

use serde::{Deserialize, Serialize};

use crate::view::PromptView;

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
    Approve { password: Option<String> },
    Cancel,
    Deny { reason: String },
}
