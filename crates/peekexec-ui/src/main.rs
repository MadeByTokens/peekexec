//! peekexec-ui: the approval dialog. Started by peekexecd, one per request.
//!
//! Protocol (peekexec_proto::ui): one `Show` on stdin before the window
//! opens; afterwards `WrongPassword` may arrive. Answers go to stdout. The
//! dialog exits when stdin closes.

mod code;
mod fonts;

use std::io::{BufReader, Write};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{
    self, Align, Color32, Event, Key, Layout, RichText, ScrollArea, TextEdit, Vec2, ViewportCommand,
};
use peekexec_proto::ui::{FromUi, Secret, ToUi};
use peekexec_proto::view::{self, Approval, PromptView, Provenance, Shown, ViewKind};
use peekexec_proto::wire::{read_msg, write_msg};
use peekexec_proto::DisplayTier;

use code::{DisplayLine, Highlighter, DANGER, WARN};

/// No core dumps, and no ptrace or /proc/<pid>/mem access by other
/// processes of the same user: the password lives in this process.
#[cfg(target_os = "linux")]
fn harden() {
    // SAFETY: plain prctl call with constant arguments.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
}

#[cfg(not(target_os = "linux"))]
fn harden() {
    // M4 (macOS): ptrace(PT_DENY_ATTACH).
}

fn main() {
    // The dialog only ever needs the approving user's rights.
    // SAFETY: trivial libc getters.
    if unsafe { libc::geteuid() == 0 || libc::getegid() == 0 } {
        fail("refusing to run as root");
    }
    harden();

    let mut stdin = BufReader::new(std::io::stdin());
    let view = match read_msg::<_, ToUi>(&mut stdin) {
        Ok(Some(ToUi::Show { view })) => *view,
        Ok(None) => return,
        Ok(Some(other)) => fail(&format!("expected Show, got {other:?}")),
        Err(e) => fail(&format!("bad message from daemon: {e}")),
    };

    let title = if view.dev_mode {
        "peekexec — DEVELOPMENT MODE request"
    } else {
        "peekexec — root access requested"
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(title)
            .with_inner_size([900.0, 640.0])
            .with_min_inner_size([560.0, 420.0])
            .with_active(true),
        centered: true,
        persist_window: false,
        ..Default::default()
    };
    let result = eframe::run_native(
        "peekexec",
        options,
        Box::new(move |cc| {
            let (tx, rx) = mpsc::channel();
            let ctx = cc.egui_ctx.clone();
            std::thread::spawn(move || loop {
                let msg = read_msg::<_, ToUi>(&mut stdin).ok().flatten();
                let closed = msg.is_none();
                if tx.send(msg).is_err() {
                    break;
                }
                ctx.request_repaint();
                if closed {
                    break;
                }
            });
            let glyphs = fonts::install(&cc.egui_ctx);
            Ok(Box::new(Dialog::new(view, rx, glyphs)))
        }),
    );
    if let Err(e) = result {
        fail(&format!("cannot open the dialog window: {e}"));
    }
}

fn fail(msg: &str) -> ! {
    eprintln!("peekexec-ui: {msg}");
    std::process::exit(1)
}

fn answer(msg: &FromUi) {
    let mut out = std::io::stdout().lock();
    if write_msg(&mut out, msg).is_err() {
        std::process::exit(1);
    }
    let _ = out.flush();
}

struct Dialog {
    view: PromptView,
    glyphs: &'static fonts::Glyphs,
    /// `None` = the daemon closed our stdin.
    rx: Receiver<Option<ToUi>>,
    highlighter: Highlighter,
    /// Cached display lines per (tab, raw, dark).
    cache: Option<((usize, bool, bool), Vec<DisplayLine>)>,
    findings: usize,
    password: String,
    error: Option<String>,
    shake_until: f64,
    busy: bool,
    answered: bool,
    deny_open: bool,
    deny_text: String,
    raw: bool,
    tab: usize,
    opened_at: Option<f64>,
    want_focus: bool,
    /// The desktop's own prompt is up (system-prompt approval).
    system_prompt_open: bool,
    /// Keys arrived while the window was opening: the human was typing
    /// into something else (perhaps a password), so Enter must not approve.
    typed_early: bool,
}

impl Dialog {
    fn new(view: PromptView, rx: Receiver<Option<ToUi>>, glyphs: &'static fonts::Glyphs) -> Self {
        let findings = view.findings();
        Dialog {
            view,
            glyphs,
            rx,
            highlighter: Highlighter::new(),
            cache: None,
            findings,
            password: String::new(),
            error: None,
            shake_until: 0.0,
            busy: false,
            answered: false,
            deny_open: false,
            deny_text: String::new(),
            raw: false,
            tab: 0,
            opened_at: None,
            want_focus: true,
            system_prompt_open: false,
            typed_early: false,
        }
    }

    fn send(&mut self, ctx: &egui::Context, msg: FromUi) {
        let closes = !matches!(msg, FromUi::Approve { .. });
        answer(&msg);
        if closes {
            self.answered = true;
            ctx.send_viewport_cmd(ViewportCommand::Close);
        } else {
            self.busy = true;
        }
    }

    /// Every way of approving goes through here, so each one waits out the
    /// approve delay (Enter as much as the button).
    fn approve(&mut self, ctx: &egui::Context, now: f64) {
        let early = delay_left(self.view.approve_delay_ms, self.opened_at, now) > 0.0;
        if early || self.busy || (self.view.wants_password && self.password.is_empty()) {
            return;
        }
        // Moved, not copied: the Secret is wiped once sent.
        let password = std::mem::take(&mut self.password);
        let password = self.view.wants_password.then(|| Secret::new(password));
        self.error = None;
        self.send(ctx, FromUi::Approve { password });
    }

    fn poll_daemon(&mut self, ctx: &egui::Context, now: f64) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Some(ToUi::WrongPassword { attempts_left }) => {
                    self.busy = false;
                    self.error = Some(format!(
                        "Wrong password — {attempts_left} attempt{} left",
                        if attempts_left == 1 { "" } else { "s" }
                    ));
                    self.shake_until = now + 0.45;
                    self.want_focus = true;
                }
                Some(ToUi::SystemPromptOpen) => {
                    self.error = None;
                    self.system_prompt_open = true;
                }
                Some(ToUi::Show { .. }) => {}
                None => {
                    // The daemon decided (approved, cancelled, timed out).
                    self.answered = true;
                    ctx.send_viewport_cmd(ViewportCommand::Close);
                }
            }
        }
    }
}

impl eframe::App for Dialog {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        let now = ctx.input(|i| i.time);
        if self.opened_at.is_none() {
            // Window managers may not focus a new window on their own.
            ctx.send_viewport_cmd(ViewportCommand::Focus);
        }
        let opened = *self.opened_at.get_or_insert(now);
        self.poll_daemon(&ctx, now);

        // Keystrokes aimed at another window must not land in the dialog.
        if now - opened < self.view.input_guard_ms as f64 / 1000.0 {
            ctx.input_mut(|i| {
                let before = i.events.len();
                i.events
                    .retain(|e| !matches!(e, Event::Key { .. } | Event::Text(_) | Event::Paste(_)));
                self.typed_early |= i.events.len() != before;
            });
            ctx.request_repaint_after(Duration::from_millis(50));
        }
        if ctx.input(|i| i.viewport().close_requested()) && !self.answered {
            answer(&FromUi::Cancel);
            self.answered = true;
        }
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::NONE, Key::Escape)) {
            self.send(&ctx, FromUi::Cancel);
        }
        let page = ctx.input_mut(|i| {
            let up = i.consume_key(egui::Modifiers::NONE, Key::PageUp);
            let down = i.consume_key(egui::Modifiers::NONE, Key::PageDown);
            match (up, down) {
                (true, _) => 1.0,
                (_, true) => -1.0,
                _ => 0.0,
            }
        });
        let dark = ctx.global_style().visuals.dark_mode;

        // The header ends with requester text (variables, why): however
        // long it gets, it scrolls within 45% of the window, so the code
        // below stays in view, and the daemon's facts come first.
        let max_header = ctx.content_rect().height() * 0.45;
        egui::Panel::top("who").show(ui, |ui| {
            ScrollArea::vertical()
                .id_salt("who")
                .max_height(max_header)
                .min_scrolled_height(max_header)
                .auto_shrink([false, true])
                .show(ui, |ui| self.header(ui, dark));
        });
        egui::Panel::bottom("answer").show(ui, |ui| self.footer(ui, &ctx, now, opened));
        egui::CentralPanel::default().show(ui, |ui| self.code(ui, dark, page));

        let remaining = self.view.timeout_secs as f64 - (now - opened);
        if remaining > 0.0 {
            ctx.request_repaint_after(Duration::from_millis(500));
        }
        if self.shake_until > now {
            ctx.request_repaint();
        }
    }
}

impl Dialog {
    fn header(&mut self, ui: &mut egui::Ui, _dark: bool) {
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            let heading = match (self.view.kind, self.view.dev_mode) {
                (ViewKind::Register, _) => RichText::new("Register an agent session"),
                (ViewKind::Root, true) => {
                    RichText::new("Development-mode request (not root)").color(WARN)
                }
                (ViewKind::Root, false) => RichText::new("Root access requested"),
            };
            ui.heading(heading.strong());
        });
        ui.add_space(2.0);
        self.provenance_badge(ui);
        ui.add_space(4.0);
        egui::Grid::new("facts")
            .num_columns(2)
            .spacing([12.0, 3.0])
            .show(ui, |ui| {
                ui.label(RichText::new("From").weak());
                ui.horizontal_wrapped(|ui| {
                    ui.spacing_mut().item_spacing.x = 0.0;
                    for (i, p) in self.view.requester.iter().take(12).enumerate() {
                        if i > 0 {
                            ui.label(RichText::new(self.glyphs.arrow).weak());
                        }
                        let name = if i == 0 {
                            format!("{} (pid {})", p.name(), p.pid)
                        } else {
                            p.name()
                        };
                        let text = if p.trusted {
                            RichText::new(name)
                        } else {
                            RichText::new(format!("{name} {}", self.glyphs.warn)).color(WARN)
                        };
                        let exe = p.exe.as_deref().unwrap_or("?");
                        let origin = if p.trusted {
                            "a root-owned program"
                        } else {
                            "a program anyone running as this user could have put there \
                             (names in this chain may be chosen by the process itself)"
                        };
                        ui.label(text).on_hover_text(format!(
                            "pid {}\nexecutable (reported by the kernel): {exe}\n  {origin}\n\
                             command line (set by the process): {}",
                            p.pid,
                            view::join(&p.cmdline, " ")
                        ));
                    }
                    if self.view.requester.len() > 12 {
                        ui.label(RichText::new(format!("{}…", self.glyphs.arrow)).weak());
                    }
                    ui.label(format!("   [user {}]", self.view.requester_user));
                });
                ui.end_row();
                ui.label(RichText::new("In").weak());
                ui.label(self.view.cwd.as_str());
                ui.end_row();
                ui.label(RichText::new("Runs as").weak());
                ui.label(RichText::new(self.view.run_as.as_str()).strong());
                ui.end_row();
            });
        ui.add_space(4.0);
        let summary = match self.view.kind {
            ViewKind::Root => self.view.summary(self.findings),
            ViewKind::Register => Vec::new(),
        };
        ui.horizontal_wrapped(|ui| {
            for (warn, text) in summary {
                let (icon, color) = if warn {
                    (self.glyphs.warn, WARN)
                } else {
                    (self.glyphs.ok, Color32::from_rgb(46, 160, 67))
                };
                ui.label(
                    RichText::new(format!("{icon} {text}"))
                        .color(color)
                        .strong(),
                );
                ui.add_space(10.0);
            }
        });
        for note in &self.view.notes {
            ui.label(
                RichText::new(format!("{} {note}", self.glyphs.warn))
                    .color(WARN)
                    .small(),
            );
        }
        // What the requester chose, in bulk, after everything the daemon
        // checked: variables, then its own words.
        if !self.view.env.is_empty() {
            egui::Grid::new("env")
                .num_columns(2)
                .spacing([12.0, 3.0])
                .show(ui, |ui| {
                    for (k, v) in &self.view.env {
                        ui.label(RichText::new("Env").weak());
                        ui.monospace(format!("{}={}", k.as_str(), v.as_str()));
                        ui.end_row();
                    }
                });
        }
        if let Some(why) = &self.view.why {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new("The requester says:").weak().small());
                ui.label(RichText::new(format!("“{why}”")).italics());
                ui.label(RichText::new("(unverified)").weak().small());
            });
        }
        ui.add_space(6.0);
    }

    /// Which registered agent session this request comes from, if any.
    /// Deliberately neutral: being inside the agent's process tree does not
    /// prove the agent itself decided to ask.
    fn provenance_badge(&self, ui: &mut egui::Ui) {
        if self.view.kind == ViewKind::Register {
            return;
        }
        let forward = if self.glyphs.arrow.contains('←') {
            " → "
        } else {
            " > "
        };
        match &self.view.provenance {
            Provenance::InSession {
                agent,
                since,
                path,
                command,
                ..
            } => {
                // Plain, not a badge of trust: ancestry shows where the
                // request came from, not that the agent itself decided to
                // ask (any program it ran could have).
                ui.label(RichText::new(format!(
                    "From inside {agent}'s session (registered {since}): any program it runs \
                     can ask from here too"
                )));
                let chain = std::iter::once(agent.as_str())
                    .chain(path.iter().map(Shown::as_str))
                    .collect::<Vec<_>>()
                    .join(forward);
                let shown = ui.label(RichText::new(chain).monospace().small());
                if let Some(cmd) = command {
                    shown.on_hover_text(format!("{agent}'s shell ran:\n{cmd}"));
                }
                if let Provenance::InSession { others, .. } = &self.view.provenance {
                    if !others.is_empty() {
                        self.script_banner(ui, agent, others);
                    }
                }
            }
            Provenance::Unregistered => {
                ui.label(RichText::new("Not from a registered agent session").weak());
            }
        }
    }

    /// Full-width warning: something other than the agent's own shell sits
    /// between the agent and this request.
    fn script_banner(&self, ui: &mut egui::Ui, agent: &str, others: &[Shown]) {
        ui.add_space(4.0);
        egui::Frame::new()
            .fill(WARN)
            .inner_margin(egui::Margin::symmetric(10, 6))
            .corner_radius(4.0)
            .show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    RichText::new(format!(
                        "{} A script or program that {agent} started may be asking, not {agent} itself:",
                        self.glyphs.warn
                    ))
                    .color(Color32::WHITE)
                    .strong(),
                );
                ui.label(
                    RichText::new(view::join(others, ", "))
                        .color(Color32::WHITE)
                        .monospace()
                        .strong(),
                );
            });
    }

    fn code(&mut self, ui: &mut egui::Ui, dark: bool, page: f32) {
        ui.horizontal(|ui| {
            for (i, s) in self.view.sections.iter().enumerate() {
                let n = s.formatted.len();
                let label = format!("{} ({n} line{})", s.title, if n == 1 { "" } else { "s" });
                if ui.selectable_label(self.tab == i, label).clicked() {
                    self.tab = i;
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.selectable_value(&mut self.raw, true, "Raw")
                    .on_hover_text("Exactly what executes, byte for byte");
                ui.selectable_value(&mut self.raw, false, "Formatted")
                    .on_hover_text("Line breaks and indentation added for reading only");
            });
        });
        let Some(section) = self.view.sections.get(self.tab) else {
            return;
        };
        let key = (self.tab, self.raw, dark);
        if self.cache.as_ref().map(|(k, _)| *k) != Some(key) {
            let lines = self.highlighter.lines(section, self.raw, dark);
            self.cache = Some((key, lines));
        }
        let lines = &self.cache.as_ref().expect("just filled").1;
        let digits = lines
            .iter()
            .map(|l| l.number)
            .max()
            .unwrap_or(1)
            .to_string()
            .len();
        let height = ui.available_height();
        egui::Frame::group(ui.style()).show(ui, |ui| {
            // Vertical only: long lines wrap, so nothing hides off to the right.
            ScrollArea::vertical()
                .auto_shrink([false, false])
                .max_height(height - 12.0)
                .show(ui, |ui| {
                    if page != 0.0 {
                        ui.scroll_with_delta(Vec2::new(0.0, page * (height - 60.0).max(40.0)));
                    }
                    ui.spacing_mut().item_spacing.y = 1.0;
                    // How it runs, in full, above what it runs: each
                    // argument is a line of its own that wraps, never cut.
                    for fact in &section.invocation {
                        ui.add(
                            egui::Label::new(
                                RichText::new(fact.as_str())
                                    .monospace()
                                    .color(code::invocation_color(dark)),
                            )
                            .wrap(),
                        );
                    }
                    if !section.invocation.is_empty() {
                        ui.separator();
                    }
                    for line in lines {
                        let job = code::layout(line, digits, dark, self.glyphs.cont);
                        ui.add(egui::Label::new(job).wrap());
                    }
                });
        });
    }

    fn footer(&mut self, ui: &mut egui::Ui, ctx: &egui::Context, now: f64, opened: f64) {
        ui.add_space(8.0);
        if self.deny_open {
            ui.label("Tell the requester why (they receive this text):");
            ui.add(
                TextEdit::multiline(&mut self.deny_text)
                    .desired_rows(2)
                    .desired_width(f32::INFINITY)
                    .hint_text("e.g. use the vendor's udev rules file instead of chmod 777"),
            );
            ui.horizontal(|ui| {
                let can_send = !self.deny_text.trim().is_empty();
                if ui
                    .add_enabled(can_send, egui::Button::new("Send denial"))
                    .clicked()
                {
                    let reason = self.deny_text.trim().to_string();
                    self.send(ctx, FromUi::Deny { reason });
                }
                if ui.button("Back").clicked() {
                    self.deny_open = false;
                    self.want_focus = true;
                }
            });
            ui.add_space(8.0);
            return;
        }

        let shake = if self.shake_until > now {
            ((now * 60.0).sin() * 8.0) as f32
        } else {
            0.0
        };
        ui.horizontal(|ui| {
            ui.add_space(8.0 + shake.max(0.0));
            if self.view.approval == Approval::SystemPrompt {
                let text = if self.system_prompt_open {
                    "Waiting for your desktop's password dialog…"
                } else {
                    "Read the request, then continue: your desktop will ask for your password."
                };
                ui.label(RichText::new(text).strong());
            }
            if self.view.wants_password {
                ui.label("Password:");
                let field = ui.add_enabled(
                    !self.busy,
                    TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(260.0)
                        .hint_text(if self.busy {
                            "checking…"
                        } else if self.view.enter_approves && !self.typed_early {
                            "type it and press Enter"
                        } else {
                            "type it, then click Approve"
                        }),
                );
                if self.want_focus && !self.busy {
                    field.request_focus();
                    self.want_focus = false;
                }
                // With warnings on screen, or keys that were typed as the
                // window opened, approving takes a deliberate click.
                if self.view.enter_approves
                    && !self.typed_early
                    && field.lost_focus()
                    && ui.input(|i| i.key_pressed(Key::Enter))
                {
                    self.approve(ctx, now);
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(8.0);
                let wait = delay_left(self.view.approve_delay_ms, Some(opened), now);
                let ready = wait <= 0.0
                    && !self.busy
                    && (!self.view.wants_password || !self.password.is_empty());
                let verb = match self.view.approval {
                    Approval::Password => "Approve",
                    Approval::SystemPrompt => "Continue",
                };
                let label = if wait > 0.0 {
                    ctx.request_repaint_after(Duration::from_millis(100));
                    format!("{verb} ({})", wait.ceil() as u32)
                } else {
                    verb.to_string()
                };
                let approve = egui::Button::new(RichText::new(label).strong());
                // A pointer click only: Tab then Space or Enter would
                // otherwise activate it from the keyboard.
                if ui
                    .add_enabled(ready, approve)
                    .clicked_by(egui::PointerButton::Primary)
                {
                    self.approve(ctx, now);
                }
                if ui.button("Cancel").clicked() {
                    self.send(ctx, FromUi::Cancel);
                }
            });
        });
        if let Some(e) = &self.error {
            ui.label(RichText::new(e).color(DANGER).strong());
        }
        if self.typed_early && self.view.enter_approves && self.view.wants_password {
            ui.label(
                RichText::new(
                    "Keys were typed as this window opened, so Enter does not approve: \
                     click Approve.",
                )
                .color(WARN),
            );
        }
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            let remaining = (self.view.timeout_secs as f64 - (now - opened)).max(0.0) as u64;
            let tier = match (self.view.display_verified, self.view.display_tier) {
                (false, _) => "display server NOT verified",
                (true, DisplayTier::X11) => {
                    "X11: other programs of yours can read and type into this window"
                }
                (true, DisplayTier::Wayland) => "Wayland: isolated from other apps",
            };
            ui.label(
                RichText::new(format!(
                    "sha256 {}…{}   ·   {tier}   ·   closes in {}:{:02}",
                    &self.view.sha256[..8],
                    &self.view.sha256[self.view.sha256.len() - 4..],
                    remaining / 60,
                    remaining % 60
                ))
                .weak()
                .small(),
            )
            .on_hover_text(format!("sha256 {}", self.view.sha256));
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(8.0);
                if ui.link("Deny with reason…").clicked() {
                    self.deny_open = true;
                }
            });
        });
        ui.add_space(6.0);
    }
}

/// Seconds until Approve may be used: `delay_ms` after the window first
/// drew (`opened`, in egui's clock); the whole delay before it has drawn.
fn delay_left(delay_ms: u32, opened: Option<f64>, now: f64) -> f64 {
    let delay = f64::from(delay_ms) / 1000.0;
    match opened {
        Some(t) => delay - (now - t),
        None => delay,
    }
}

#[cfg(test)]
mod tests {
    use super::delay_left;

    #[test]
    fn the_approve_delay_counts_from_the_first_frame() {
        assert!(delay_left(2000, None, 100.0) > 0.0);
        assert!(delay_left(2000, Some(100.0), 101.0) > 0.0);
        assert!(delay_left(2000, Some(100.0), 102.0) <= 0.0);
        assert!(delay_left(0, Some(100.0), 100.0) <= 0.0);
    }
}
