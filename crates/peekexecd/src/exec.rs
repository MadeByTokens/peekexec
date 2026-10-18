//! Running an approved [`Execution`].

use std::io::{self, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;

use crate::platform::{ExecPlan, Sandbox};

/// Output kept per stream; the rest is drained and dropped.
pub const OUTPUT_CAP: u64 = 16 * 1024 * 1024;

pub struct Outcome {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
}

pub fn run(sandbox: &dyn Sandbox, plan: &ExecPlan) -> Result<Outcome, String> {
    let mut child = sandbox.spawn(plan).map_err(|e| e.to_string())?;
    let out = child.stdout.take().expect("piped");
    let err = child.stderr.take().expect("piped");
    let out = std::thread::spawn(move || capture(out));
    let err = std::thread::spawn(move || capture(err));
    let status = child.wait().map_err(|e| format!("wait: {e}"))?;
    let exit_code = status
        .code()
        .or_else(|| status.signal().map(|s| 128 + s))
        .unwrap_or(1);
    Ok(Outcome {
        exit_code,
        stdout: out.join().unwrap_or_default(),
        stderr: err.join().unwrap_or_default(),
    })
}

fn capture(mut r: impl Read) -> String {
    let mut buf = Vec::new();
    let _ = r.by_ref().take(OUTPUT_CAP).read_to_end(&mut buf);
    let dropped = io::copy(&mut r, &mut io::sink()).unwrap_or(0);
    let mut s = String::from_utf8_lossy(&buf).into_owned();
    if dropped > 0 {
        s.push_str(&format!("\n[peekexec: {dropped} more bytes dropped]\n"));
    }
    s
}

/// Atomically replace (or create) `dest` with `content`: write a temporary
/// file next to it, fsync, rename. An existing file keeps its mode.
pub fn install(dest: &Path, content: &[u8], id: &str) -> Result<Outcome, String> {
    let dir = dest.parent().ok_or("destination has no parent")?;
    let mode = std::fs::metadata(dest)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o644);
    let tmp = dir.join(format!(".peekexec-{id}.tmp"));
    let err = |what: &str, e: io::Error| format!("{what} {}: {e}", tmp.display());
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| err("create", e))?;
    let written = f
        .write_all(content)
        .and_then(|()| f.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| f.sync_all());
    if let Err(e) = written {
        let _ = std::fs::remove_file(&tmp);
        return Err(err("write", e));
    }
    if let Err(e) = std::fs::rename(&tmp, dest) {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!("rename into {}: {e}", dest.display()));
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(Outcome {
        exit_code: 0,
        stdout: format!("installed {} ({} bytes)\n", dest.display(), content.len()),
        stderr: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn install_replaces_atomically_and_keeps_mode() {
        let dir = std::env::temp_dir().join(format!("pe-install-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let dest = dir.join("x.conf");
        install(&dest, b"one\n", "a").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"one\n");
        std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o640)).unwrap();
        install(&dest, b"two\n", "b").unwrap();
        assert_eq!(std::fs::read(&dest).unwrap(), b"two\n");
        let mode = std::fs::metadata(&dest).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "temp file left behind"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
