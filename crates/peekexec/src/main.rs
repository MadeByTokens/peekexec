use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};
use peekexec_core::display::shell_join;
use peekexec_core::textcheck::{scan, scan_bytes, Finding};
use peekexec_core::{Action, Request};
use peekexec_proto::{Response, Status};

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
    /// More help: `agents` (guide for automated callers) or `schema` (JSON Schema of --json output)
    Help { topic: Option<Topic> },
}

#[derive(Subcommand)]
enum ActionCmd {
    /// Run a command as root
    Run(RunArgs),
    /// Run a script file as root (snapshotted: edits after submission have no effect)
    Script(ScriptArgs),
    /// Copy a file as root (the human sees a diff); may write only DEST
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
    /// Pass an environment variable (repeatable). Default: clean environment
    #[arg(long = "env", value_name = "K=V", value_parser = parse_env)]
    env: Vec<(String, String)>,
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
    let cwd = std::env::current_dir().map_err(|e| format!("no current directory: {e}"))?;
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

/// Plain-text stand-in for the dialog until the egui UI lands (M1).
fn print_preview(req: &Request) {
    println!("peekexec preview: what the human will be asked to approve\n");
    println!("requester : pid {} in {}", std::process::id(), req.cwd);
    if let Some(why) = &req.why {
        println!("says      : {why:?}  (unverified)");
    }
    match &req.write {
        Some(paths) => println!("writes    : {}", paths.join(", ")),
        None => println!("writes    : UNRESTRICTED  (flagged)"),
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
        println!("{:>4}  {line}", i + 1);
    }
}

fn emit(resp: &Response, json: bool) -> ExitCode {
    if json {
        println!(
            "{}",
            serde_json::to_string(resp).expect("response serializes")
        );
    } else if let Some(err) = &resp.error {
        eprintln!("peekexec: {err}");
    }
    let code = match resp.status {
        Status::Approved => resp.exit_code.unwrap_or(0).clamp(0, 255) as u8,
        s => s
            .exit_code()
            .expect("non-approved statuses have exit codes"),
    };
    ExitCode::from(code)
}

const NOT_YET: &str =
    "peekexecd is not implemented yet (milestone M1); only `preview` and `help` work";

fn main() -> ExitCode {
    let matches = Cli::command().after_help(help::after_help()).get_matches();
    let cli = match Cli::from_arg_matches(&matches) {
        Ok(cli) => cli,
        Err(e) => e.exit(),
    };
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
        Cmd::Preview { action } => match build_request(&action) {
            Ok(req) if cli.json => {
                let out = serde_json::json!({
                    "request": req,
                    "sha256": req.digest(),
                    "findings": findings(&req),
                });
                println!("{out}");
                ExitCode::SUCCESS
            }
            Ok(req) => {
                print_preview(&req);
                ExitCode::SUCCESS
            }
            Err(e) => emit(&Response::error(e), cli.json),
        },
        Cmd::Action(action) | Cmd::Submit { action } => match build_request(&action) {
            Ok(_) => emit(&Response::error(NOT_YET), cli.json),
            Err(e) => emit(&Response::error(e), cli.json),
        },
        Cmd::Wait { .. } | Cmd::Cancel { .. } => emit(&Response::error(NOT_YET), cli.json),
    }
}
