use std::collections::BTreeMap;
use std::io::BufReader;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use peekexec_core::display::shell_join;
use peekexec_core::textcheck::{scan, scan_bytes, Finding};
use peekexec_core::{Action, Request};
use peekexec_proto::view::Shown;
use peekexec_proto::{wire, ClientMsg, PreviewReply, Response, Status};

mod help;

#[derive(Parser)]
#[command(
    name = "peekexec",
    version,
    about = help::ABOUT,
    long_about = help::LONG_ABOUT,
    disable_help_subcommand = true
)]
struct Cli {
    /// Print one JSON object on stdout; command output is inside it
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(flatten)]
    Action(ActionCmd),
    /// Show what the human would see; no root, no prompt
    Preview {
        #[command(subcommand)]
        action: ActionCmd,
    },
    /// Like run/script/install, but return a request id immediately
    Submit {
        #[command(subcommand)]
        action: ActionCmd,
    },
    /// Wait for a submitted request
    Wait {
        id: String,
        /// Give up after this many seconds and report "pending"
        #[arg(long)]
        timeout: Option<u32>,
    },
    /// Withdraw a pending request (the dialog closes)
    Cancel { id: String },
    /// Register your agent session (one dialog), so later requests are
    /// labelled as coming from your session
    Register {
        /// Name shown on your requests, e.g. "Claude Code"
        #[arg(long, default_value = "agent")]
        name: String,
        /// The agent process [default: nearest ancestor that is not a shell]
        #[arg(long, value_name = "PID")]
        agent_pid: Option<u32>,
        /// Why you are registering, shown to the human marked "unverified"
        #[arg(long)]
        why: Option<String>,
        /// Seconds the human has to respond
        #[arg(long, default_value_t = 120)]
        timeout: u32,
    },
    /// End your agent session's registration
    Unregister,
    /// More help: `agents` (guide for automated callers) or `schema` (JSON Schema of --json output)
    Help { topic: Option<Topic> },
}

#[derive(Subcommand)]
enum ActionCmd {
    /// Run a command as root
    Run(RunArgs),
    /// Run a script file as root (snapshotted: edits after submission have no effect)
    Script(ScriptArgs),
    /// Copy a file as root (the human sees it, and a diff when replacing); writes only DEST
    Install(InstallArgs),
}

#[derive(Clone, Copy, ValueEnum)]
enum Topic {
    Agents,
    Schema,
}

#[derive(Args)]
struct Scope {
    /// Your explanation, shown to the human marked "unverified". Say what and why
    #[arg(long)]
    why: Option<String>,
    /// Path the command may modify (repeatable). Omit = unrestricted (flagged to the human)
    #[arg(long = "write", value_name = "PATH")]
    write: Vec<PathBuf>,
    /// Block network access
    #[arg(long)]
    no_net: bool,
    /// Set an environment variable (repeatable). Default: clean environment. Only harmless
    /// variables are accepted: DEBIAN_FRONTEND, LANG, LC_*, TZ, TERM, NO_COLOR, ...
    #[arg(long = "env", value_name = "K=V", value_parser = parse_env)]
    env: Vec<(String, String)>,
    /// Run in DIR instead of /. Flagged to the human when you own DIR: programs
    /// may load code or settings from their working directory
    #[arg(long, value_name = "DIR")]
    cwd: Option<PathBuf>,
    /// Seconds the human has to respond
    #[arg(long, default_value_t = 120)]
    timeout: u32,
}

#[derive(Args)]
struct RunArgs {
    #[command(flatten)]
    scope: Scope,
    #[arg(
        required = true,
        trailing_var_arg = true,
        allow_hyphen_values = true,
        value_name = "CMD"
    )]
    cmd: Vec<String>,
}

#[derive(Args)]
struct ScriptArgs {
    #[command(flatten)]
    scope: Scope,
    file: PathBuf,
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,
}

#[derive(Args)]
struct InstallArgs {
    #[command(flatten)]
    scope: Scope,
    src: PathBuf,
    dest: PathBuf,
}

fn parse_env(s: &str) -> Result<(String, String), String> {
    s.split_once('=')
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .ok_or_else(|| format!("expected K=V, got {s:?}"))
}

fn utf8_path(p: &Path) -> Result<String, String> {
    p.to_str()
        .map(str::to_string)
        .ok_or_else(|| format!("path is not valid UTF-8: {}", p.display()))
}

fn absolute(p: &Path) -> Result<String, String> {
    let abs = std::path::absolute(p).map_err(|e| format!("{}: {e}", p.display()))?;
    utf8_path(&abs)
}

fn read(p: &Path) -> Result<Vec<u8>, String> {
    std::fs::read(p).map_err(|e| format!("cannot read {}: {e}", p.display()))
}

fn build_request(action: &ActionCmd) -> Result<Request, String> {
    let (scope, action, implied_write) = match action {
        ActionCmd::Run(a) => (
            &a.scope,
            Action::Run {
                argv: a.cmd.clone(),
            },
            None,
        ),
        ActionCmd::Script(a) => (
            &a.scope,
            Action::Script {
                path: absolute(&a.file)?,
                content: read(&a.file)?,
                args: a.args.clone(),
            },
            None,
        ),
        ActionCmd::Install(a) => {
            let dest = absolute(&a.dest)?;
            let action = Action::Install {
                src: absolute(&a.src)?,
                content: read(&a.src)?,
                dest: dest.clone(),
            };
            (&a.scope, action, Some(vec![dest]))
        }
    };
    let write = if scope.write.is_empty() {
        implied_write
    } else {
        Some(
            scope
                .write
                .iter()
                .map(|p| absolute(p))
                .collect::<Result<_, _>>()?,
        )
    };
    // Root runs in / unless asked otherwise: a directory the requester owns
    // can feed code to the program (git hooks, Python modules, Makefiles).
    let cwd = match &scope.cwd {
        Some(dir) => PathBuf::from(absolute(dir)?),
        None => PathBuf::from("/"),
    };
    Ok(Request {
        action,
        why: scope.why.clone(),
        write,
        no_net: scope.no_net,
        env: scope.env.iter().cloned().collect::<BTreeMap<_, _>>(),
        cwd: utf8_path(&cwd)?,
        timeout_secs: scope.timeout,
    })
}

fn findings(req: &Request) -> Vec<Finding> {
    match &req.action {
        Action::Run { argv } => scan(&argv.join(" ")),
        Action::Script { content, .. } | Action::Install { content, .. } => scan_bytes(content),
    }
}

fn socket() -> PathBuf {
    std::env::var_os("PEEKEXEC_SOCKET")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(wire::SOCKET))
}

/// The uid the daemon at the other end of `conn` runs as.
fn daemon_uid(conn: &UnixStream) -> std::io::Result<u32> {
    #[cfg(target_os = "linux")]
    {
        use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
        Ok(getsockopt(conn, PeerCredentials)?.uid())
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(nix::unistd::getpeereid(conn)?.0.as_raw())
    }
}

/// The reply, and whether root sent it. Anything that can set this
/// process's environment can name another socket (PEEKEXEC_SOCKET), and a
/// program of the user's listening there could forge any answer, a
/// `deny_reason` included. Only a daemon running as root speaks for the
/// human.
fn call<A: serde::de::DeserializeOwned>(msg: &ClientMsg) -> Result<(A, bool), String> {
    let path = socket();
    let exchange = || -> std::io::Result<(A, bool)> {
        let mut conn = UnixStream::connect(&path)?;
        let from_root = daemon_uid(&conn)? == 0;
        wire::write_msg(&mut conn, msg)?;
        let reply = wire::read_msg(&mut BufReader::new(conn))?.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "daemon closed the connection without replying",
            )
        })?;
        Ok((reply, from_root))
    };
    exchange().map_err(|e| {
        if e.kind() == std::io::ErrorKind::PermissionDenied {
            return format!(
                "cannot connect to {}: only members of the administrator group (sudo, wheel \
                 or admin) may use peekexec. If you were just added to it, log out and back in.",
                path.display()
            );
        }
        format!(
            "cannot reach peekexecd at {}: {e}. Is peekexec installed and peekexecd.socket enabled?",
            path.display()
        )
    })
}

fn preview(req: Request, json: bool) -> ExitCode {
    match call::<PreviewReply>(&ClientMsg::Preview {
        request: req.clone(),
    }) {
        Ok((PreviewReply::Ok { view }, from_root)) => {
            if !from_root && !json {
                eprintln!(
                    "peekexec: the daemon at {} does not run as root: this is not necessarily \
                     what the human would see",
                    socket().display()
                );
            }
            // Counted as the daemon and the dialog count them
            // (PromptView::findings): the content and the invocation lines.
            let found: Vec<Finding> = view
                .sections
                .iter()
                .flat_map(|s| {
                    let invocation = s.invocation.iter().flat_map(|l| scan(l));
                    scan(&s.raw).into_iter().chain(invocation)
                })
                .collect();
            debug_assert_eq!(found.len(), view.findings());
            if json {
                let mut out = serde_json::json!({ "view": view, "findings": found });
                if !from_root {
                    out["dev_mode"] = true.into();
                }
                println!("{out}");
            } else {
                print!("{}", view.to_text(found.len()));
            }
            ExitCode::SUCCESS
        }
        // The daemon would reject this request: say why, as `run` would.
        Ok((PreviewReply::Error { error }, from_root)) => emit(
            &Response {
                dev_mode: !from_root,
                ..Response::error(error)
            },
            json,
        ),
        Err(unreachable) => {
            if json {
                let out = serde_json::json!({
                    "request": req,
                    "sha256": req.digest(),
                    "findings": findings(&req),
                    "warning": unreachable,
                });
                println!("{out}");
            } else {
                println!("({unreachable}\n Showing a local approximation instead.)\n");
                print_local_preview(&req);
            }
            ExitCode::SUCCESS
        }
    }
}

/// Used only when the daemon is unreachable; the real view comes from it.
fn print_local_preview(req: &Request) {
    if let Some(why) = &req.why {
        println!("says      : {why:?}  (unverified)");
    }
    match &req.write {
        Some(paths) => println!("writes    : {}", paths.join(", ")),
        None => println!("writes    : ANYWHERE"),
    }
    println!(
        "network   : {}",
        if req.no_net { "blocked" } else { "allowed" }
    );
    for (k, v) in &req.env {
        println!("env       : {k}={v}");
    }
    println!();
    match &req.action {
        Action::Run { argv } => println!("$ {}", shell_join(argv)),
        Action::Script {
            path,
            content,
            args,
        } => {
            let argv: Vec<String> = std::iter::once(path.clone())
                .chain(args.iter().cloned())
                .collect();
            println!("script {}", shell_join(&argv));
            print_numbered(content);
        }
        Action::Install { src, content, dest } => {
            println!("install {src} -> {dest}");
            print_numbered(content);
        }
    }
    let found = findings(req);
    if !found.is_empty() {
        println!("\nsuspicious characters:");
        for f in &found {
            println!(
                "  line {} col {}: {} {:?}",
                f.line, f.column, f.codepoint, f.kind
            );
        }
    }
    println!("\nsha256    : {}", req.digest());
}

fn print_numbered(content: &[u8]) {
    for (i, line) in String::from_utf8_lossy(content).lines().enumerate() {
        println!("{:>4}  {}", i + 1, Shown::line(line, usize::MAX));
    }
}

fn emit(resp: &Response, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string(resp).expect("response serializes")
        );
    } else {
        print_human(resp);
    }
    let code = match resp.status {
        Status::Approved => resp.exit_code.unwrap_or(0).clamp(0, 255) as u8,
        s => s
            .exit_code()
            .expect("non-approved statuses have exit codes"),
    };
    ExitCode::from(code)
}

fn print_human(resp: &Response) {
    use std::io::Write;
    if resp.dev_mode {
        eprintln!(
            "peekexec: the daemon at {} does not run as root (development mode, or a program \
             posing as peekexecd): nothing ran as root, and this answer is not from the human",
            socket().display()
        );
    }
    // Text from the daemon goes to a terminal: escaped, one line.
    let line = |s: Option<&str>, none: &str| Shown::line(s.unwrap_or(none), 2000);
    let id = line(resp.request_id.as_deref(), "?");
    match resp.status {
        Status::Approved => {
            let _ = std::io::stdout().write_all(resp.stdout.as_deref().unwrap_or("").as_bytes());
            let _ = std::io::stderr().write_all(resp.stderr.as_deref().unwrap_or("").as_bytes());
        }
        Status::Pending => {
            eprintln!("peekexec: waiting for the human; check with `peekexec wait {id}`")
        }
        Status::Denied => eprintln!(
            "peekexec: denied by the human: {}",
            line(resp.deny_reason.as_deref(), "(no reason given)")
        ),
        Status::Cancelled => eprintln!("peekexec: cancelled"),
        Status::AuthFailed => eprintln!("peekexec: authentication failed"),
        Status::Timeout => eprintln!("peekexec: no answer before the timeout"),
        Status::Error => eprintln!("peekexec: {}", line(resp.error.as_deref(), "unknown error")),
    }
}

fn request_or_exit(action: &ActionCmd, json: bool) -> Result<Request, ExitCode> {
    build_request(action).map_err(|e| emit(&Response::error(e), json))
}

/// A daemon not running as root ran nothing as root, and its status and
/// `deny_reason` are not the human's: the response says so (`dev_mode`).
fn call_response(msg: &ClientMsg) -> Response {
    match call::<Response>(msg) {
        Ok((mut resp, from_root)) => {
            if !from_root {
                resp.dev_mode = true;
            }
            resp
        }
        Err(e) => Response::error(e),
    }
}

fn send(msg: ClientMsg, json: bool) -> ExitCode {
    emit(&call_response(&msg), json)
}

fn main() -> ExitCode {
    let matches = Cli::command().after_help(help::after_help()).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
    let json = cli.json;
    match cli.command {
        Cmd::Help { topic: None } => {
            Cli::command()
                .after_help(help::after_help())
                .print_long_help()
                .ok();
            ExitCode::SUCCESS
        }
        Cmd::Help {
            topic: Some(Topic::Agents),
        } => {
            print!("{}", help::AGENT_GUIDE);
            ExitCode::SUCCESS
        }
        Cmd::Help {
            topic: Some(Topic::Schema),
        } => {
            let schema = schemars::schema_for!(Response);
            println!(
                "{}",
                serde_json::to_string_pretty(&schema).expect("schema serializes")
            );
            ExitCode::SUCCESS
        }
        Cmd::Preview { action } => match request_or_exit(&action, json) {
            Ok(request) => preview(request, json),
            Err(code) => code,
        },
        Cmd::Action(action) => match request_or_exit(&action, json) {
            Ok(request) => send(ClientMsg::Run { request }, json),
            Err(code) => code,
        },
        Cmd::Submit { action } => match request_or_exit(&action, json) {
            Ok(request) => {
                let resp = call_response(&ClientMsg::Submit { request });
                let code = emit(&resp, json);
                // Submitting successfully is a success, even though the
                // request itself is still pending.
                if resp.status == Status::Pending {
                    ExitCode::SUCCESS
                } else {
                    code
                }
            }
            Err(code) => code,
        },
        Cmd::Wait { id, timeout } => send(
            ClientMsg::Wait {
                id,
                timeout_secs: timeout,
            },
            json,
        ),
        Cmd::Cancel { id } => send(ClientMsg::Cancel { id }, json),
        Cmd::Register {
            name,
            agent_pid,
            why,
            timeout,
        } => send(
            ClientMsg::Register {
                name,
                agent_pid,
                why,
                timeout_secs: timeout,
            },
            json,
        ),
        Cmd::Unregister => send(ClientMsg::Unregister, json),
    }
}
