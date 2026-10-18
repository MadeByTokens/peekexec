use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use peekexecd::server::{Daemon, Options};
use peekexecd::{platform, trust};

/// Root daemon for peekexec. Normally started by systemd (peekexecd.socket).
#[derive(Parser)]
#[command(name = "peekexecd", version)]
struct Args {
    /// Development mode: run as your own user, on a private socket. Commands
    /// run as you, not as root. For testing the whole flow without installing.
    #[arg(long)]
    dev: bool,
    /// Socket to listen on when not socket-activated
    /// [default: /run/peekexec/peekexec.sock; dev: $XDG_RUNTIME_DIR/peekexec-dev.sock]
    #[arg(long)]
    socket: Option<PathBuf>,
    /// The dialog program [default: /usr/libexec/peekexec/peekexec-ui; dev: next to this binary]
    #[arg(long)]
    ui: Option<PathBuf>,
    /// PAM service name
    #[arg(long, default_value = "peekexec")]
    pam_service: String,
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("peekexecd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<(), String> {
    let root = nix::unistd::geteuid().is_root();
    match (root, args.dev) {
        (false, false) => {
            return Err("must run as root (or pass --dev to test as your own user)".into())
        }
        (true, true) => return Err("--dev is for running without root; drop it".into()),
        _ => {}
    }
    let runtime = || {
        std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or("XDG_RUNTIME_DIR is not set; pass --socket")
    };
    let socket = match args.socket {
        Some(s) => s,
        None if args.dev => runtime()?.join("peekexec-dev.sock"),
        None => PathBuf::from(peekexec_proto::wire::SOCKET),
    };
    let snapshot_root = if args.dev {
        runtime()?.join("peekexec-dev/snap")
    } else {
        PathBuf::from("/run/peekexec/snap")
    };
    let dialog = match args.ui {
        Some(p) => p,
        None if args.dev => std::env::current_exe()
            .map_err(|e| format!("cannot locate myself: {e}"))?
            .with_file_name("peekexec-ui"),
        None => PathBuf::from("/usr/libexec/peekexec/peekexec-ui"),
    };
    if root {
        // The dialog collects the password: it must not be replaceable.
        trust::check(&dialog, &[0]).map_err(|e| format!("refusing dialog program: {e}"))?;
    }

    let test_approver = test_approver()?;
    let opts = Options {
        socket,
        dev: args.dev,
        dialog,
        snapshot_root,
        test_approver,
    };
    let daemon = Arc::new(Daemon::new(opts, platform::current(&args.pam_service)));
    daemon.serve()
}

#[cfg(feature = "test-approver")]
fn test_approver() -> Result<Option<String>, String> {
    use peekexecd::prompt::test_approver::ENV;
    let v = std::env::var(ENV).ok();
    if v.is_some() && nix::unistd::geteuid().is_root() {
        return Err(format!("{ENV} is set while running as root; refusing"));
    }
    if v.is_some() {
        eprintln!("peekexecd: TEST APPROVER ACTIVE ({ENV}); no human is asked");
    }
    Ok(v)
}

#[cfg(not(feature = "test-approver"))]
fn test_approver() -> Result<Option<String>, String> {
    Ok(None)
}
