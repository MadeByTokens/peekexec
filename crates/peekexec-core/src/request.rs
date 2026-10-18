use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// What will run as root. File contents are carried inline: the daemon
/// executes these bytes, never the caller's file on disk.
///
/// Paths are `String`, not `PathBuf`: the client rejects non-UTF-8 paths so
/// that every byte shown to the human is also exactly representable here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    Run {
        argv: Vec<String>,
    },
    Script {
        path: String,
        content: Vec<u8>,
        args: Vec<String>,
    },
    Install {
        src: String,
        content: Vec<u8>,
        dest: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub action: Action,
    /// The caller's explanation. Shown to the human as unverified.
    pub why: Option<String>,
    /// Paths the command may modify. `None` means unrestricted.
    pub write: Option<Vec<String>>,
    pub no_net: bool,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    pub timeout_secs: u32,
}

impl Request {
    /// SHA-256 (hex) of everything that determines what executes.
    ///
    /// `why` and `timeout_secs` are left out on purpose: rewording the
    /// explanation of a denied request must not make it a "new" request.
    pub fn digest(&self) -> String {
        #[derive(Serialize)]
        struct Executed<'a> {
            v: u8,
            action: &'a Action,
            write: &'a Option<Vec<String>>,
            no_net: bool,
            env: &'a BTreeMap<String, String>,
            cwd: &'a str,
        }
        let executed = Executed {
            v: 1,
            action: &self.action,
            write: &self.write,
            no_net: self.no_net,
            env: &self.env,
            cwd: &self.cwd,
        };
        // Only strings, byte vectors, bools and BTreeMaps: serialization cannot fail.
        let bytes = serde_json::to_vec(&executed).expect("plain data always serializes");
        Sha256::digest(bytes)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Request {
        Request {
            action: Action::Run {
                argv: vec!["udevadm".into(), "trigger".into()],
            },
            why: Some("reload rules".into()),
            write: Some(vec!["/etc/udev/rules.d".into()]),
            no_net: true,
            env: BTreeMap::new(),
            cwd: "/home/u".into(),
            timeout_secs: 120,
        }
    }

    #[test]
    fn digest_ignores_why_and_timeout() {
        let a = sample();
        let mut b = sample();
        b.why = Some("something else entirely".into());
        b.timeout_secs = 5;
        assert_eq!(a.digest(), b.digest());
    }

    #[test]
    fn digest_covers_what_executes() {
        let a = sample();
        let mut b = sample();
        b.no_net = false;
        assert_ne!(a.digest(), b.digest());
        let mut c = sample();
        c.write = None;
        assert_ne!(a.digest(), c.digest());
    }

    #[test]
    fn digest_is_hex_sha256() {
        let d = sample().digest();
        assert_eq!(d.len(), 64);
        assert!(d.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
