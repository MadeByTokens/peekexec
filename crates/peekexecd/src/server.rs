//! Connections, the request table, and the life of one request:
//! identify → prepare → (one dialog at a time) ask → execute → report.

use std::collections::HashMap;
use std::io::{BufReader, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use peekexec_core::{Action, Request};
use peekexec_proto::wire::{read_msg, write_msg};
use peekexec_proto::{ClientMsg, DisplayTier, PreviewReply, Response, Status};

use crate::exec;
use crate::platform::{Peer, Platform};
use crate::prepare::{self, Ctx, Execution, Prepared, User};
use crate::prompt::{self, Decision, Dialog};
use crate::session::{self, Display};

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
/// Requests a user may have waiting at once; more are refused.
const MAX_PENDING_PER_USER: usize = 3;
/// A dialog appearing this soon after the previous one closed gets a longer
/// keystroke guard and a note, against reflexive approval.
const BACK_TO_BACK: Duration = Duration::from_secs(10);
/// Open connections a user may hold at once.
const MAX_CONNECTIONS_PER_USER: usize = 16;

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
        }
    }

    pub fn serve(self: Arc<Self>) -> Result<(), String> {
        let listener = self
            .platform
            .listener
            .listen(&self.opts.socket, !self.opts.dev)
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

    fn ctx(&self) -> Ctx<'_> {
        Ctx {
            sandbox: self.platform.sandbox.as_ref(),
            wants_password: self.platform.auth.wants_password(),
            dev: self.opts.dev,
            snapshot_root: &self.opts.snapshot_root,
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
        prepare::prepare(
            &self.ctx(),
            peer,
            &user,
            request,
            "preview",
            &display,
            false,
        )
        .map(|p| p.view)
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
        let prepared = match prepare::prepare(&self.ctx(), peer, &user, request, id, &display, true)
        {
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
                    "This request arrived right after the previous one. Read it before approving."
                        .into(),
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
        prompt::ask(
            &dialog,
            display,
            &prepared.view,
            self.platform.auth.as_ref(),
            &user.name,
            cancel,
        )
    }

    fn execute(&self, prepared: &Prepared, id: &str, base: Response) -> Response {
        let outcome = match &prepared.exec {
            Execution::Command(plan) => exec::run(self.platform.sandbox.as_ref(), plan),
            Execution::Install { dest, content } => exec::install(dest, content, id),
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
    Ok(User {
        name: u.name,
        home: u.dir.to_string_lossy().into_owned(),
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
