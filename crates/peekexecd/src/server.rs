//! Connections, the request table, and the life of one request:
//! identify → prepare → (one dialog at a time) ask → execute → report.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use peekexec_core::{Action, Request};
use peekexec_proto::wire::{read_msg, write_msg};
use peekexec_proto::{ClientMsg, DisplayTier, PreviewReply, Response, Status};

use crate::exec;
use crate::inspect::{self, Creds, Inspection};
use crate::platform::{Peer, Platform, ProcessInfo};
use crate::prepare::{self, display_line, proc_line, Ctx, Execution, Prepared, User};
use crate::prompt::{self, Decision, Dialog};
use crate::session::{self, Display};
use crate::sessions::{self, AgentSession};
use crate::trust;
use peekexec_core::format::verbatim;
use peekexec_proto::view::{
    self, Approval, PromptView, Provenance, Section, Shown, Syntax, ViewKind,
};
use peekexec_proto::{Enforced, Level};

pub struct Options {
    pub socket: PathBuf,
    pub dev: bool,
    pub dialog: PathBuf,
    pub snapshot_root: PathBuf,
    /// Value of PEEKEXEC_TEST_APPROVER (test builds only).
    pub test_approver: Option<String>,
}

/// How long a denial blocks an identical request, and how long finished
/// results stay available to `wait`.
const DENIAL_TTL: Duration = Duration::from_secs(3600);
const RESULT_TTL: Duration = Duration::from_secs(900);
const ADMIN_GROUPS: &[&str] = &["sudo", "wheel", "admin"];
/// This very binary, for the inspection helper (even if the file on disk
/// was replaced since the daemon started).
const SELF_EXE: &str = "/proc/self/exe";
/// Requests a user may have waiting at once; more are refused.
const MAX_PENDING_PER_USER: usize = 3;
/// A dialog appearing this soon after the previous one closed gets a longer
/// keystroke guard and a note, against reflexive approval.
const BACK_TO_BACK: Duration = Duration::from_secs(10);
/// Open connections a user may hold at once.
const MAX_CONNECTIONS_PER_USER: usize = 16;
/// Registered agent sessions a user may have at once.
const MAX_AGENTS_PER_USER: usize = 4;

pub struct Daemon {
    opts: Options,
    platform: Platform,
    requests: Mutex<HashMap<String, Arc<Entry>>>,
    denials: Mutex<HashMap<(u32, String), (Instant, String)>>,
    /// One dialog on screen at a time.
    prompt_lock: Mutex<()>,
    /// When the last dialog closed.
    last_prompt: Mutex<Option<Instant>>,
    /// Open connections per uid.
    connections: Mutex<HashMap<u32, usize>>,
    /// Agent processes the human registered.
    agents: Mutex<Vec<AgentSession>>,
}

struct Entry {
    owner: u32,
    created: Instant,
    cancel: AtomicBool,
    result: Mutex<Option<Response>>,
    done: Condvar,
}

impl Entry {
    fn finish(&self, r: Response) {
        *self.result.lock().unwrap() = Some(r);
        self.done.notify_all();
    }

    /// The final response, or `None` if still pending after `timeout`.
    fn wait(&self, timeout: Option<Duration>) -> Option<Response> {
        let guard = self.result.lock().unwrap();
        let guard = match timeout {
            None => self.done.wait_while(guard, |r| r.is_none()).unwrap(),
            Some(t) => {
                self.done
                    .wait_timeout_while(guard, t, |r| r.is_none())
                    .unwrap()
                    .0
            }
        };
        guard.clone()
    }
}

impl Daemon {
    pub fn new(opts: Options, platform: Platform) -> Self {
        Daemon {
            opts,
            platform,
            requests: Mutex::default(),
            denials: Mutex::default(),
            prompt_lock: Mutex::new(()),
            last_prompt: Mutex::new(None),
            connections: Mutex::default(),
            agents: Mutex::default(),
        }
    }

    pub fn serve(self: Arc<Self>) -> Result<(), String> {
        let group = if self.opts.dev {
            None
        } else {
            Some(admin_gid().ok_or_else(|| {
                format!(
                    "no administrator group ({}) on this system",
                    ADMIN_GROUPS.join(", ")
                )
            })?)
        };
        let listener = self
            .platform
            .listener
            .listen(&self.opts.socket, group)
            .map_err(|e| e.to_string())?;
        eprintln!(
            "peekexecd: listening on {}{}",
            self.opts.socket.display(),
            if self.opts.dev {
                " (development mode)"
            } else {
                ""
            }
        );
        for conn in listener.incoming() {
            match conn {
                Ok(conn) => {
                    let d = Arc::clone(&self);
                    // On failure the closure, and with it the connection, is dropped.
                    if let Err(e) = std::thread::Builder::new().spawn(move || d.handle(conn)) {
                        eprintln!("peekexecd: cannot start a thread: {e}");
                    }
                }
                Err(e) => {
                    eprintln!("peekexecd: accept: {e}");
                    // e.g. out of file descriptors: back off instead of spinning.
                    std::thread::sleep(Duration::from_millis(200));
                }
            }
        }
        Ok(())
    }

    fn handle(self: Arc<Self>, mut conn: UnixStream) {
        let peer = match self.platform.peer.identify(&conn) {
            Ok(p) => p,
            Err(e) => {
                let _ = write_msg(
                    &mut conn,
                    &Response::error(format!("cannot identify caller: {e}")),
                );
                return;
            }
        };
        // Only administrators can ever be asked, so nobody else gets to send
        // (and make the daemon buffer) a request at all.
        if !self.opts.dev {
            let admin = user_of(peer.uid).is_ok_and(|u| is_admin(&u.name, peer.gid));
            if !admin {
                eprintln!(
                    "peekexecd: audit rejected uid={} pid={} exe={:?} reason=\"not an administrator\"",
                    peer.uid,
                    peer.process.pid,
                    peer.process.exe.as_deref().unwrap_or("?")
                );
                let _ = write_msg(
                    &mut conn,
                    &Response::error(format!(
                        "uid {} is not in an administrator group ({})",
                        peer.uid,
                        ADMIN_GROUPS.join(", ")
                    )),
                );
                return;
            }
        }
        let Some(_slot) = ConnectionSlot::take(&self.connections, peer.uid) else {
            let _ = write_msg(
                &mut conn,
                &Response::error("too many open connections; close some and retry"),
            );
            return;
        };
        let Ok(read_half) = conn.try_clone() else {
            return;
        };
        let mut reader = BufReader::new(read_half);
        // A client gets this long to send its request; then the timeout is
        // lifted, since `run` keeps the connection open while it waits.
        let _ = conn.set_read_timeout(Some(Duration::from_secs(30)));
        let msg: ClientMsg = match read_msg(&mut reader) {
            Ok(Some(m)) => m,
            Ok(None) => return,
            Err(e) => {
                let _ = write_msg(&mut conn, &Response::error(format!("bad request: {e}")));
                return;
            }
        };
        let _ = conn.set_read_timeout(None);
        let reply = match msg {
            ClientMsg::Preview { request } => {
                let reply = match self.preview(&peer, &request) {
                    Ok(view) => PreviewReply::Ok {
                        view: Box::new(view),
                    },
                    Err(error) => PreviewReply::Error { error },
                };
                let _ = write_msg(&mut conn, &reply);
                return;
            }
            ClientMsg::Run { request } => {
                let (_, entry) = self.start(peer, request);
                // The client hanging up (Ctrl-C) withdraws the request.
                let watcher = Arc::clone(&entry);
                let _ = std::thread::Builder::new().spawn(move || {
                    let _ = reader.read(&mut [0u8; 1]);
                    watcher.cancel.store(true, Ordering::SeqCst);
                });
                entry.wait(None).expect("waits until finished")
            }
            ClientMsg::Submit { request } => {
                let (id, _) = self.start(peer, request);
                Response {
                    request_id: Some(id),
                    ..Response::new(Status::Pending)
                }
            }
            ClientMsg::Wait { id, timeout_secs } => match self.lookup(&id, peer.uid) {
                Some(entry) => entry
                    .wait(timeout_secs.map(|s| Duration::from_secs(s.into())))
                    .unwrap_or_else(|| pending(&id)),
                None => Response::error(format!("no such request: {id}")),
            },
            ClientMsg::Register {
                name,
                agent_pid,
                why,
                timeout_secs,
            } => self.register(&peer, &name, agent_pid, why.as_deref(), timeout_secs),
            ClientMsg::Unregister => self.unregister(&peer),
            ClientMsg::Cancel { id } => match self.lookup(&id, peer.uid) {
                Some(entry) => {
                    entry.cancel.store(true, Ordering::SeqCst);
                    entry
                        .wait(Some(Duration::from_secs(10)))
                        .unwrap_or_else(|| pending(&id))
                }
                None => Response::error(format!("no such request: {id}")),
            },
        };
        let _ = write_msg(&mut conn, &reply);
    }

    fn lookup(&self, id: &str, uid: u32) -> Option<Arc<Entry>> {
        // Other users' requests are reported as nonexistent.
        let requests = self.requests.lock().unwrap();
        requests.get(id).filter(|e| e.owner == uid).cloned()
    }

    fn start(self: &Arc<Self>, peer: Peer, request: Request) -> (String, Arc<Entry>) {
        let id = new_id();
        let entry = Arc::new(Entry {
            owner: peer.uid,
            created: Instant::now(),
            cancel: AtomicBool::new(false),
            result: Mutex::new(None),
            done: Condvar::new(),
        });
        {
            let mut requests = self.requests.lock().unwrap();
            requests.retain(|_, e| {
                e.created.elapsed() < RESULT_TTL || e.result.lock().unwrap().is_none()
            });
            let pending = requests
                .values()
                .filter(|e| e.owner == peer.uid && e.result.lock().unwrap().is_none())
                .count();
            requests.insert(id.clone(), Arc::clone(&entry));
            if pending >= MAX_PENDING_PER_USER {
                entry.finish(Response {
                    request_id: Some(id.clone()),
                    ..Response::error(format!(
                        "refused: {pending} requests are already waiting for the human; \
                         wait for them before sending more"
                    ))
                });
                return (id, entry);
            }
        }
        let d = Arc::clone(self);
        let worker_entry = Arc::clone(&entry);
        let worker_id = id.clone();
        let spawned = std::thread::Builder::new().spawn(move || {
            let response = d.process(&peer, &request, &worker_id, &worker_entry.cancel);
            audit(&peer, &request, &worker_id, &response);
            worker_entry.finish(response);
        });
        if let Err(e) = spawned {
            entry.finish(Response::error(format!(
                "daemon overloaded ({e}); try again"
            )));
        }
        (id, entry)
    }

    fn ctx<'a>(&'a self, inspect: &'a prepare::Inspector) -> Ctx<'a> {
        Ctx {
            sandbox: self.platform.sandbox.as_ref(),
            inspect,
            wants_password: self.platform.auth.wants_password(),
            dev: self.opts.dev,
            snapshot_root: &self.opts.snapshot_root,
        }
    }

    /// Inspection with the requesting user's authority (design rule 1): in
    /// a helper process as that user, or in-process in development mode,
    /// where the daemon is that user already.
    fn inspector(
        &self,
        user: &User,
    ) -> impl Fn(&Request, &[u32]) -> Result<(Inspection, OwnedFd), String> + Sync {
        let creds = (!self.opts.dev).then(|| Creds {
            uid: user.uid,
            gid: user.gid,
            groups: user.groups.clone(),
        });
        move |request: &Request, owners: &[u32]| match &creds {
            Some(c) => inspect::inspect_as(Path::new(SELF_EXE), Some(c), request, owners),
            None => inspect::inspect(request, owners),
        }
    }

    fn preview(
        &self,
        peer: &Peer,
        request: &Request,
    ) -> Result<peekexec_proto::view::PromptView, String> {
        let user = user_of(peer.uid)?;
        // Preview runs as root (it inspects install targets): admins only.
        if !self.opts.dev && !is_admin(&user.name, peer.gid) {
            return Err(format!(
                "user {} is not in an administrator group ({})",
                user.name,
                ADMIN_GROUPS.join(", ")
            ));
        }
        let display = self.display_for(peer).unwrap_or(Display {
            vars: Vec::new(),
            tier: DisplayTier::X11,
            verified: false,
        });
        let inspect = self.inspector(&user);
        prepare::prepare(
            &self.ctx(&inspect),
            peer,
            &user,
            request,
            "preview",
            &display,
            false,
        )
        .map(|p| {
            let mut view = p.view;
            self.apply_provenance(peer, &mut view);
            if self.system_prompt_for(&display).is_some() {
                prepare::use_system_prompt(&mut view);
            }
            view
        })
    }

    fn chain(peer: &Peer) -> Vec<ProcessInfo> {
        std::iter::once(peer.process.clone())
            .chain(peer.ancestry.iter().cloned())
            .collect()
    }

    /// Where this request came from, relative to the registered agents.
    fn provenance(&self, peer: &Peer) -> Provenance {
        let chain = Self::chain(peer);
        let mut agents = self.agents.lock().unwrap();
        agents.retain(|s| self.platform.peer.alive(&s.pinned));
        let mine: Vec<&AgentSession> = agents.iter().filter(|s| s.uid == peer.uid).collect();
        let owners = trust::trusted_owners();
        let is_live = |s: &AgentSession, p: &ProcessInfo| {
            p.pid == s.pinned.pid && p.start_time == Some(s.pinned.start_time)
        };
        let trusted = |exe: &str| trust::check(std::path::Path::new(exe), &owners).is_ok();
        let since = |name: &str| {
            mine.iter()
                .find(|s| s.name == name)
                .map(|s| hhmm(s.registered_at))
                .unwrap_or_default()
        };
        match sessions::classify(&chain, &mine, &is_live, &trusted) {
            sessions::Provenance::Unregistered => Provenance::Unregistered,
            sessions::Provenance::InSession {
                session,
                path,
                others,
                command,
            } => Provenance::InSession {
                since: display_line(&since(&session), 20),
                agent: display_line(&session, 60),
                path: path.iter().map(|p| display_line(p, 60)).collect(),
                others: others.iter().map(|p| display_line(p, 60)).collect(),
                command: command.map(|c| display_line(&c, 600)),
            },
        }
    }

    fn apply_provenance(&self, peer: &Peer, view: &mut PromptView) {
        let provenance = self.provenance(peer);
        // Shown by the dialog as a banner (not a note); approving it takes a
        // click, after a short delay.
        if let Provenance::InSession { others, .. } = &provenance {
            if !others.is_empty() {
                view.enter_approves = false;
                view.approve_delay_ms = 2000;
            }
        }
        view.provenance = provenance;
    }

    fn register(
        &self,
        peer: &Peer,
        name: &str,
        agent_pid: Option<u32>,
        why: Option<&str>,
        timeout_secs: u32,
    ) -> Response {
        let id = format!("s-{}", &new_id()[2..]);
        let fail = |m: String| Response {
            request_id: Some(id.clone()),
            ..Response::error(m)
        };
        let user = match user_of(peer.uid) {
            Ok(u) => u,
            Err(e) => return fail(e),
        };
        let name = match display_line(name.trim(), 40).into_string() {
            n if n.is_empty() => "agent".to_string(),
            n => n,
        };
        let chain = Self::chain(peer);
        let agent = match agent_pid {
            Some(pid) => chain.iter().find(|p| p.pid == pid),
            None => sessions::default_agent(&chain),
        };
        let Some(agent) = agent else {
            return fail(match agent_pid {
                Some(pid) => format!("pid {pid} is neither the caller nor one of its ancestors"),
                None => "no agent process among the caller's ancestors (only shells, or the \
                         caller was orphaned); pass --agent-pid"
                    .into(),
            });
        };
        let Some(start_time) = agent.start_time else {
            return fail(format!("cannot read the start time of pid {}", agent.pid));
        };
        {
            let mut agents = self.agents.lock().unwrap();
            agents.retain(|s| self.platform.peer.alive(&s.pinned));
            if let Some(s) = agents.iter().find(|s| {
                s.uid == peer.uid && s.pinned.pid == agent.pid && s.pinned.start_time == start_time
            }) {
                return Response {
                    session: Some(s.id.clone()),
                    stdout: Some(format!("already registered as \"{}\"\n", s.name)),
                    ..Response::new(Status::Approved)
                };
            }
            if agents.iter().filter(|s| s.uid == peer.uid).count() >= MAX_AGENTS_PER_USER {
                return fail(format!(
                    "refused: {MAX_AGENTS_PER_USER} agent sessions are already registered"
                ));
            }
        }
        let Some(pinned) = self.platform.peer.pin(agent.pid, start_time) else {
            return fail(format!("cannot pin pid {} (it may have exited)", agent.pid));
        };
        let display = if self.opts.test_approver.is_some() {
            Some(Display {
                vars: Vec::new(),
                tier: DisplayTier::X11,
                verified: false,
            })
        } else {
            self.display_for(peer)
        };
        let Some(display) = display else {
            return fail(format!(
                "no graphical session found for {}: the dialog needs a desktop session",
                user.name
            ));
        };
        let line = proc_line(agent);
        let exe = line
            .exe
            .clone()
            .map(Shown::into_string)
            .unwrap_or_else(|| "?".into());
        let description = format!(
            "Register this process as the agent \"{name}\":\n\n  pid {} (started at tick {start_time})\n  executable: {exe}\n  command line: {}\n\nFrom now on, requests from inside this process (its own commands and \
             anything it starts) are labelled \"{name}'s session\", and scripts or programs \
             it starts that sit in between are flagged. Nothing runs as root now. The \
             registration ends when this process exits.\n",
            agent.pid,
            view::join(&line.cmdline, " "),
        );
        let mut notes = Vec::new();
        if self.opts.dev {
            notes.push("DEVELOPMENT MODE.".to_string());
        }
        if !display.verified {
            notes.push(format!("{}.", prepare::UNVERIFIED_NOTE));
        }
        if !line.trusted {
            notes.push(format!(
                "{exe} can be modified by its owner: anything running as you could replace it."
            ));
        }
        let enforced = Enforced {
            write: Some(Vec::new()),
            write_level: Level::Builtin,
            network: false,
            network_level: Level::Builtin,
        };
        let view = PromptView {
            kind: ViewKind::Register,
            approval: Approval::Password,
            provenance: Provenance::Unregistered,
            request_id: id.clone(),
            sha256: peekexec_core::request::sha256_hex(description.as_bytes()),
            requester: chain.iter().map(proc_line).collect(),
            requester_user: display_line(&user.name, 64),
            pinned: peer.pinned,
            cwd: display_line(peer.cwd.as_deref().unwrap_or("?"), 300),
            run_as: Shown::fixed("nothing runs (registration only)"),
            dev_mode: self.opts.dev,
            why: why.map(|w| display_line(w, 300)),
            enforced: enforced.clone(),
            display_tier: display.tier,
            display_verified: display.verified,
            env: Vec::new(),
            sections: vec![Section {
                title: Shown::fixed("agent session"),
                invocation: Vec::new(),
                syntax: Syntax::Plain,
                formatted: verbatim(&description),
                raw: description,
            }],
            notes: notes.iter().map(|n| display_line(n, 1000)).collect(),
            timeout_secs: timeout_secs.clamp(5, prepare::MAX_TIMEOUT_SECS),
            wants_password: self.platform.auth.wants_password(),
            input_guard_ms: 400,
            // A registration labels a whole session: always a deliberate click.
            enter_approves: false,
            approve_delay_ms: 0,
        };
        let mut view = view;
        if self.system_prompt_for(&display).is_some() {
            prepare::use_system_prompt(&mut view);
        }
        let prepared = Prepared {
            view,
            exec: Execution::Nothing,
            enforced,
            snapshot_dir: None,
        };
        let cancel = AtomicBool::new(false);
        let decision = {
            let _one_at_a_time = self.prompt_lock.lock().unwrap();
            let d = self.decide(&prepared, &display, &user, peer, &cancel);
            *self.last_prompt.lock().unwrap() = Some(Instant::now());
            d
        };
        let base = |status| Response {
            request_id: Some(id.clone()),
            dev_mode: self.opts.dev,
            display_tier: Some(display.tier),
            display_verified: Some(display.verified),
            ..Response::new(status)
        };
        let response = match decision {
            Ok(Decision::Approved) => {
                self.agents.lock().unwrap().push(AgentSession {
                    id: id.clone(),
                    name: name.clone(),
                    uid: peer.uid,
                    pinned,
                    registered_at: std::time::SystemTime::now(),
                });
                Response {
                    session: Some(id.clone()),
                    ..base(Status::Approved)
                }
            }
            Ok(Decision::Cancelled) => base(Status::Cancelled),
            Ok(Decision::TimedOut) => base(Status::Timeout),
            Ok(Decision::AuthFailed) => base(Status::AuthFailed),
            Ok(Decision::Failed(msg)) => fail(msg),
            Ok(Decision::Denied(reason)) => Response {
                deny_reason: Some(reason),
                ..base(Status::Denied)
            },
            Err(e) => fail(e),
        };
        eprintln!(
            "peekexecd: audit register id={id} uid={} pid={} agent_pid={} agent_exe={exe:?} name={name:?} status={}",
            peer.uid,
            peer.process.pid,
            agent.pid,
            response.status.as_str()
        );
        response
    }

    fn unregister(&self, peer: &Peer) -> Response {
        let chain = Self::chain(peer);
        let mut agents = self.agents.lock().unwrap();
        let before = agents.len();
        agents.retain(|s| {
            !(s.uid == peer.uid
                && chain
                    .iter()
                    .any(|p| p.pid == s.pinned.pid && p.start_time == Some(s.pinned.start_time)))
        });
        let removed = before - agents.len();
        Response {
            stdout: Some(format!("removed {removed} agent session(s)\n")),
            ..Response::new(Status::Approved)
        }
    }

    fn display_for(&self, peer: &Peer) -> Option<Display> {
        session::find(self.platform.peer.as_ref(), peer)
    }

    fn process(&self, peer: &Peer, request: &Request, id: &str, cancel: &AtomicBool) -> Response {
        let base = |status| Response {
            request_id: Some(id.to_string()),
            sha256: Some(request.digest()),
            dev_mode: self.opts.dev,
            ..Response::new(status)
        };
        let fail = |msg: String| Response {
            error: Some(msg),
            ..base(Status::Error)
        };

        let digest = request.digest();
        if let Some(msg) = self.denied_before(peer.uid, &digest) {
            return fail(msg);
        }
        let user = match user_of(peer.uid) {
            Ok(u) => u,
            Err(e) => return fail(e),
        };
        if !self.opts.dev && !is_admin(&user.name, peer.gid) {
            return fail(format!(
                "user {} is not in an administrator group ({}); peekexec only asks administrators",
                user.name,
                ADMIN_GROUPS.join(", ")
            ));
        }
        let found = if self.opts.test_approver.is_some() {
            Some(Display {
                vars: Vec::new(),
                tier: DisplayTier::X11,
                verified: false,
            })
        } else {
            self.display_for(peer)
        };
        // Validate the request before anything else, so callers get the
        // specific reason a request is refused whatever display there is.
        let display = found.clone().unwrap_or(Display {
            vars: Vec::new(),
            tier: DisplayTier::X11,
            verified: false,
        });
        let inspect = self.inspector(&user);
        let ctx = self.ctx(&inspect);
        let prepared = match prepare::prepare(&ctx, peer, &user, request, id, &display, true) {
            Ok(p) => p,
            Err(e) => return fail(e),
        };
        if found.is_none() {
            if let Some(dir) = &prepared.snapshot_dir {
                let _ = std::fs::remove_dir_all(dir);
            }
            return fail(format!(
                "no graphical session found for {}: the dialog needs a desktop session",
                user.name
            ));
        }

        let mut prepared = prepared;
        self.apply_provenance(peer, &mut prepared.view);
        if self.system_prompt_for(&display).is_some() {
            prepare::use_system_prompt(&mut prepared.view);
        }
        let decision = {
            let _one_at_a_time = self.prompt_lock.lock().unwrap();
            let recent = self
                .last_prompt
                .lock()
                .unwrap()
                .is_some_and(|t| t.elapsed() < BACK_TO_BACK);
            if recent {
                prepared.view.input_guard_ms = 1500;
                prepared.view.enter_approves = false;
                prepared.view.notes.insert(
                    0,
                    Shown::fixed(
                        "This request arrived right after the previous one. Read it before \
                         approving.",
                    ),
                );
            }
            let d = if cancel.load(Ordering::SeqCst) {
                Ok(Decision::Cancelled)
            } else {
                self.decide(&prepared, &display, &user, peer, cancel)
            };
            *self.last_prompt.lock().unwrap() = Some(Instant::now());
            d
        };

        let mut response = match decision {
            Ok(Decision::Approved) => self.execute(&prepared, id, base(Status::Approved)),
            Ok(Decision::Cancelled) => base(Status::Cancelled),
            Ok(Decision::TimedOut) => base(Status::Timeout),
            Ok(Decision::AuthFailed) => base(Status::AuthFailed),
            Ok(Decision::Failed(msg)) => fail(msg),
            Ok(Decision::Denied(reason)) => {
                self.denials
                    .lock()
                    .unwrap()
                    .insert((peer.uid, digest), (Instant::now(), reason.clone()));
                Response {
                    deny_reason: Some(reason),
                    ..base(Status::Denied)
                }
            }
            Err(e) => fail(e),
        };
        response.enforced = Some(prepared.enforced.clone());
        response.display_tier = Some(display.tier);
        response.display_verified = Some(display.verified);
        if let Some(dir) = &prepared.snapshot_dir {
            let _ = std::fs::remove_dir_all(dir);
        }
        response
    }

    fn decide(
        &self,
        prepared: &Prepared,
        display: &Display,
        user: &User,
        peer: &Peer,
        cancel: &AtomicBool,
    ) -> Result<Decision, String> {
        #[cfg(feature = "test-approver")]
        if let Some(answer) = &self.opts.test_approver {
            return Ok(prompt::test_approver::decide(
                answer,
                &prepared.view,
                cancel,
            ));
        }
        let dialog = Dialog {
            program: self.opts.dialog.clone(),
            run_as: (!self.opts.dev).then_some((peer.uid, peer.gid)),
        };
        let approver = match self.system_prompt_for(display) {
            Some(prompt) if prepared.view.approval == Approval::SystemPrompt => {
                prompt::Approver::System {
                    prompt,
                    subject: &peer.process,
                    uid: peer.uid,
                    message: prepare::system_prompt_message(&prepared.view),
                }
            }
            _ => prompt::Approver::Password {
                auth: self.platform.auth.as_ref(),
                user: &user.name,
            },
        };
        prompt::ask(&dialog, display, &prepared.view, &approver, cancel)
    }

    /// The desktop's own prompt, used when this display cannot be verified.
    fn system_prompt_for(&self, display: &Display) -> Option<&dyn crate::platform::SystemPrompt> {
        if display.verified || self.opts.test_approver.is_some() {
            return None;
        }
        self.platform
            .system_prompt
            .as_deref()
            .filter(|p| p.available())
    }

    fn execute(&self, prepared: &Prepared, id: &str, base: Response) -> Response {
        let outcome = match &prepared.exec {
            Execution::Command(plan) => exec::run(self.platform.sandbox.as_ref(), plan),
            Execution::Install { dest, content } => exec::install(dest, content, id),
            Execution::Nothing => Ok(exec::Outcome {
                exit_code: 0,
                stdout: String::new(),
                stderr: String::new(),
            }),
        };
        match outcome {
            Ok(o) => Response {
                exit_code: Some(o.exit_code),
                stdout: Some(o.stdout),
                stderr: Some(o.stderr),
                ..base
            },
            Err(e) => Response {
                status: Status::Error,
                error: Some(format!("approved, but could not run: {e}")),
                ..base
            },
        }
    }

    fn denied_before(&self, uid: u32, digest: &str) -> Option<String> {
        let mut denials = self.denials.lock().unwrap();
        denials.retain(|_, (at, _)| at.elapsed() < DENIAL_TTL);
        denials.get(&(uid, digest.to_string())).map(|(at, reason)| {
            format!(
                "refused: the human denied this exact request (sha256 {}) {} min ago, saying: {reason:?}. \
                 Change the request instead of resending it.",
                &digest[..12],
                at.elapsed().as_secs() / 60
            )
        })
    }
}

/// One counted connection of a user; released when dropped.
struct ConnectionSlot<'a> {
    table: &'a Mutex<HashMap<u32, usize>>,
    uid: u32,
}

impl<'a> ConnectionSlot<'a> {
    fn take(table: &'a Mutex<HashMap<u32, usize>>, uid: u32) -> Option<Self> {
        let mut t = table.lock().unwrap();
        let n = t.entry(uid).or_insert(0);
        if *n >= MAX_CONNECTIONS_PER_USER {
            return None;
        }
        *n += 1;
        Some(ConnectionSlot { table, uid })
    }
}

impl Drop for ConnectionSlot<'_> {
    fn drop(&mut self) {
        let mut t = self.table.lock().unwrap();
        if let Some(n) = t.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                t.remove(&self.uid);
            }
        }
    }
}

/// Local wall-clock time as HH:MM.
fn hhmm(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    // SAFETY: localtime_r writes into the zeroed tm we own.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    if unsafe { libc::localtime_r(&secs, &mut tm) }.is_null() {
        return String::new();
    }
    format!("{:02}:{:02}", tm.tm_hour, tm.tm_min)
}

fn pending(id: &str) -> Response {
    Response {
        request_id: Some(id.to_string()),
        ..Response::new(Status::Pending)
    }
}

fn user_of(uid: u32) -> Result<User, String> {
    let u = nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
        .map_err(|e| format!("cannot look up uid {uid}: {e}"))?
        .ok_or_else(|| format!("uid {uid} has no user entry"))?;
    let groups = groups_of(&u.name, u.gid.as_raw());
    Ok(User {
        name: u.name,
        home: u.dir.to_string_lossy().into_owned(),
        uid,
        gid: u.gid.as_raw(),
        groups,
    })
}

#[cfg(target_os = "linux")]
fn groups_of(user: &str, gid: u32) -> Vec<u32> {
    use nix::unistd::{getgrouplist, Gid};
    std::ffi::CString::new(user)
        .ok()
        .and_then(|name| getgrouplist(&name, Gid::from_raw(gid)).ok())
        .map(|gs| gs.into_iter().map(|g| g.as_raw()).collect())
        .unwrap_or_else(|| vec![gid])
}

#[cfg(not(target_os = "linux"))]
fn groups_of(_user: &str, gid: u32) -> Vec<u32> {
    vec![gid]
}

/// The first administrator group that exists here.
fn admin_gid() -> Option<u32> {
    ADMIN_GROUPS.iter().find_map(|name| {
        nix::unistd::Group::from_name(name)
            .ok()
            .flatten()
            .map(|g| g.gid.as_raw())
    })
}

#[cfg(target_os = "linux")]
fn is_admin(user: &str, gid: u32) -> bool {
    use nix::unistd::{getgrouplist, Gid, Group};
    let Ok(name) = std::ffi::CString::new(user) else {
        return false;
    };
    getgrouplist(&name, Gid::from_raw(gid))
        .unwrap_or_default()
        .into_iter()
        .filter_map(|g| Group::from_gid(g).ok().flatten())
        .any(|g| ADMIN_GROUPS.contains(&g.name.as_str()))
}

#[cfg(not(target_os = "linux"))]
fn is_admin(_user: &str, _gid: u32) -> bool {
    false // M4: the macOS `admin` group via the platform layer
}

fn new_id() -> String {
    let mut b = [0u8; 4];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        b = (t.subsec_nanos() ^ std::process::id()).to_le_bytes();
    }
    format!(
        "r-{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// One line per request in the daemon log (the journal under systemd):
/// who asked, what exactly, where, why, and the outcome. Strings are
/// Debug-quoted so control characters cannot forge log lines.
fn audit(peer: &Peer, request: &Request, id: &str, response: &Response) {
    use peekexec_core::request::sha256_hex;
    let what = match &request.action {
        Action::Run { argv } => format!("run argv={argv:?}"),
        Action::Script {
            path,
            content,
            args,
        } => format!(
            "script path={path:?} bytes={} content_sha256={} args={args:?}",
            content.len(),
            sha256_hex(content)
        ),
        Action::Install { src, content, dest } => format!(
            "install dest={dest:?} src={src:?} bytes={} content_sha256={}",
            content.len(),
            sha256_hex(content)
        ),
    };
    eprintln!(
        "peekexecd: audit id={id} uid={} pid={} exe={:?} {what} cwd={:?} why={:?} \
         sha256={} status={}{}{}{}",
        peer.uid,
        peer.process.pid,
        peer.process.exe.as_deref().unwrap_or("?"),
        request.cwd,
        request.why.as_deref().unwrap_or(""),
        request.digest(),
        response.status.as_str(),
        response
            .exit_code
            .map(|c| format!(" exit={c}"))
            .unwrap_or_default(),
        response
            .deny_reason
            .as_deref()
            .map(|r| format!(" deny_reason={r:?}"))
            .unwrap_or_default(),
        response
            .error
            .as_deref()
            .map(|e| format!(" error={e:?}"))
            .unwrap_or_default(),
    );
}
