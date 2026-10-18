//! peekexec-ui: the approval dialog. Started by peekexecd, one per request.
//!
//! Protocol (peekexec_proto::ui): one `Show` on stdin before the window
//! opens; afterwards `WrongPassword` may arrive. Answers go to stdout. The
//! dialog exits when stdin closes.

mod code;
mod fonts;
mod grab;

use std::io::{BufReader, Write};
use std::sync::mpsc::{self, Receiver};
use std::time::Duration;

use eframe::egui::{
    self, Align, Color32, Event, Key, Layout, RichText, ScrollArea, TextEdit, Vec2, ViewportCommand,
};
use peekexec_core::textcheck::scan;
use peekexec_proto::ui::{FromUi, ToUi};
use peekexec_proto::view::PromptView;
use peekexec_proto::wire::{read_msg, write_msg};
use peekexec_proto::DisplayTier;

use code::{DisplayLine, Highlighter, DANGER, WARN};

/// Keystrokes are ignored for this long after the dialog appears, so typing
/// aimed at another window cannot land in it.
const INPUT_GUARD_SECS: f64 = 0.4;

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
            .with_always_on_top()
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

/// Overwrite a secret's bytes before dropping it.
fn scrub(s: &mut String) {
    // SAFETY: zero bytes are valid UTF-8, and the string is cleared after.
    unsafe { s.as_bytes_mut().fill(0) };
    s.clear();
}

struct Dialog {
    view: PromptView,
    glyphs: &'static fonts::Glyphs,
    grab: grab::KeyboardGrab,
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
}

impl Dialog {
    fn new(view: PromptView, rx: Receiver<Option<ToUi>>, glyphs: &'static fonts::Glyphs) -> Self {
        let findings = view.sections.iter().map(|s| scan(&s.raw).len()).sum();
        Dialog {
            view,
            glyphs,
            grab: grab::KeyboardGrab::new(),
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

    fn approve(&mut self, ctx: &egui::Context) {
        if self.busy || (self.view.wants_password && self.password.is_empty()) {
            return;
        }
        let password = self.view.wants_password.then(|| self.password.clone());
        scrub(&mut self.password);
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
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        self.grab.poll(frame);
        let now = ctx.input(|i| i.time);
        if self.opened_at.is_none() {
            // Window managers may not focus a new window on their own.
            ctx.send_viewport_cmd(ViewportCommand::Focus);
        }
        let opened = *self.opened_at.get_or_insert(now);
        self.poll_daemon(&ctx, now);

        if now - opened < INPUT_GUARD_SECS {
            ctx.input_mut(|i| {
                i.events
                    .retain(|e| !matches!(e, Event::Key { .. } | Event::Text(_) | Event::Paste(_)))
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

        egui::Panel::top("who").show(ui, |ui| self.header(ui, dark));
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
            let heading = if self.view.dev_mode {
                RichText::new("Development-mode request (not root)").color(WARN)
            } else {
                RichText::new("Root access requested")
            };
            ui.heading(heading.strong());
        });
        ui.add_space(4.0);
        egui::Grid::new("facts")
            .num_columns(2)
            .spacing([12.0, 3.0])
            .show(ui, |ui| {
                ui.label(RichText::new("From").weak());
                ui.label(format!(
                    "{}   [user {}]",
                    self.view.requester_chain(self.glyphs.arrow, 5),
                    self.view.requester_user
                ))
                .on_hover_text(
                    self.view
                        .requester
                        .iter()
                        .map(|p| format!("pid {}: {}", p.pid, p.cmdline.join(" ")))
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
                ui.end_row();
                ui.label(RichText::new("In").weak());
                ui.label(&self.view.cwd);
                ui.end_row();
                ui.label(RichText::new("Runs as").weak());
                ui.label(RichText::new(&self.view.run_as).strong());
                ui.end_row();
                if let Some(why) = &self.view.why {
                    ui.label(RichText::new("Says").weak());
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new(format!("“{why}”")).italics());
                        ui.label(
                            RichText::new("(unverified: written by the requester)")
                                .weak()
                                .small(),
                        );
                    });
                    ui.end_row();
                }
                for (k, v) in &self.view.env {
                    ui.label(RichText::new("Env").weak());
                    ui.monospace(format!("{k}={v}"));
                    ui.end_row();
                }
            });
        ui.add_space(4.0);
        ui.horizontal_wrapped(|ui| {
            for (warn, text) in self.view.summary(self.findings) {
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
        ui.add_space(6.0);
    }

    fn code(&mut self, ui: &mut egui::Ui, dark: bool, page: f32) {
        ui.horizontal(|ui| {
            for (i, s) in self.view.sections.iter().enumerate() {
                if ui.selectable_label(self.tab == i, &s.title).clicked() {
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
        if let Some(h) = &section.header {
            ui.label(RichText::new(h).monospace().weak().small());
        }
        let key = (self.tab, self.raw, dark);
        if self.cache.as_ref().map(|(k, _)| *k) != Some(key) {
            let lines = self.highlighter.lines(section, self.raw, dark);
            self.cache = Some((key, lines));
        }
        let lines = &self.cache.as_ref().expect("just filled").1;
        let digits = lines.len().to_string().len();
        let height = ui.available_height();
        egui::Frame::group(ui.style()).show(ui, |ui| {
            ScrollArea::both()
                .auto_shrink([false, false])
                .max_height(height - 12.0)
                .show(ui, |ui| {
                    if page != 0.0 {
                        ui.scroll_with_delta(Vec2::new(0.0, page * (height - 60.0).max(40.0)));
                    }
                    ui.spacing_mut().item_spacing.y = 1.0;
                    for (i, line) in lines.iter().enumerate() {
                        ui.add(
                            egui::Label::new(code::layout(
                                line,
                                i + 1,
                                digits,
                                dark,
                                self.glyphs.cont,
                            ))
                            .extend(),
                        );
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
            if self.view.wants_password {
                ui.label("Password:");
                let field = ui.add_enabled(
                    !self.busy,
                    TextEdit::singleline(&mut self.password)
                        .password(true)
                        .desired_width(260.0)
                        .hint_text(if self.busy {
                            "checking…"
                        } else {
                            "type it and press Enter"
                        }),
                );
                if self.want_focus && !self.busy {
                    field.request_focus();
                    self.want_focus = false;
                }
                if field.lost_focus() && ui.input(|i| i.key_pressed(Key::Enter)) {
                    self.approve(ctx);
                }
            }
            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                ui.add_space(8.0);
                let ready = !self.busy && (!self.view.wants_password || !self.password.is_empty());
                let approve = egui::Button::new(RichText::new("Approve").strong());
                if ui.add_enabled(ready, approve).clicked() {
                    self.approve(ctx);
                }
                if ui.button("Cancel").clicked() {
                    self.send(ctx, FromUi::Cancel);
                }
            });
        });
        if let Some(e) = &self.error {
            ui.label(RichText::new(e).color(DANGER).strong());
        }
        ui.add_space(2.0);
        ui.horizontal(|ui| {
            let remaining = (self.view.timeout_secs as f64 - (now - opened)).max(0.0) as u64;
            let tier = match (self.view.display_tier, self.grab.grabbed) {
                (DisplayTier::X11, true) => {
                    "X11, keyboard grabbed (X11 cannot fully isolate windows)"
                }
                (DisplayTier::X11, false) => "X11: other apps of yours can see this window",
                (DisplayTier::Wayland, _) => "Wayland: isolated from other apps",
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
