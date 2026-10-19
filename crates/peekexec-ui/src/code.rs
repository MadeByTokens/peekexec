//! Turning a [`Section`] into highlighted, numbered display lines.
//!
//! Characters that can disguise code (bidi overrides, invisible and control
//! characters, invalid UTF-8) are never drawn as themselves: each becomes a
//! visible red `⟨U+XXXX⟩` token. Other non-ASCII characters are drawn but
//! marked, since they may be look-alikes.

use eframe::egui::text::{LayoutJob, TextFormat};
use eframe::egui::{Color32, FontId, Stroke};
use peekexec_core::textcheck::{classify, FindingKind};
use peekexec_proto::view::{Section, Syntax};
use syntect::easy::HighlightLines;
use syntect::highlighting::{Theme, ThemeSet};
use syntect::parsing::SyntaxSet;

pub struct Highlighter {
    syntaxes: SyntaxSet,
    dark: Theme,
    light: Theme,
}

/// One display line: its number, indent, continued-from-previous, and
/// coloured spans. `collapsed` replaces a long run of blank lines.
pub struct DisplayLine {
    pub number: usize,
    pub indent: usize,
    pub continued: bool,
    pub spans: Vec<(Color32, String)>,
    pub collapsed: Option<usize>,
}

/// Runs of at least this many blank lines are shown as one marker line, so
/// padding cannot push content far below the fold unnoticed.
const BLANK_RUN: usize = 4;

impl Highlighter {
    pub fn new() -> Self {
        let themes = ThemeSet::load_defaults();
        Highlighter {
            syntaxes: SyntaxSet::load_defaults_newlines(),
            dark: themes.themes["base16-ocean.dark"].clone(),
            light: themes.themes["InspiredGitHub"].clone(),
        }
    }

    pub fn lines(&self, section: &Section, raw: bool, dark: bool) -> Vec<DisplayLine> {
        let source: Vec<(usize, bool, String)> = if raw {
            section
                .raw
                .split('\n')
                .map(|l| (0, false, l.to_string()))
                .collect()
        } else {
            section
                .formatted
                .iter()
                .map(|l| {
                    let text = l.text.trim_end_matches('\n');
                    // Formatted view re-indents; the slice's own leading
                    // whitespace is replaced by the computed indent.
                    let text = if l.indent > 0 || l.continued {
                        text.trim_start()
                    } else {
                        text
                    };
                    (l.indent, l.continued, text.to_string())
                })
                .collect()
        };
        let syntax = match section.syntax {
            Syntax::Shell => self.syntaxes.find_syntax_by_extension("sh"),
            Syntax::Diff => self.syntaxes.find_syntax_by_extension("diff"),
            Syntax::Plain => None,
        }
        .unwrap_or_else(|| self.syntaxes.find_syntax_plain_text());
        let theme = if dark { &self.dark } else { &self.light };
        let mut h = HighlightLines::new(syntax, theme);
        let lines: Vec<DisplayLine> = source
            .into_iter()
            .enumerate()
            .map(|(i, (indent, continued, text))| {
                let with_nl = format!("{text}\n");
                let spans = match h.highlight_line(&with_nl, &self.syntaxes) {
                    Ok(regions) => regions
                        .into_iter()
                        .map(|(style, s)| {
                            let c = style.foreground;
                            (
                                Color32::from_rgb(c.r, c.g, c.b),
                                s.trim_end_matches('\n').to_string(),
                            )
                        })
                        .filter(|(_, s)| !s.is_empty())
                        .collect(),
                    Err(_) => vec![(default_fg(dark), text)],
                };
                DisplayLine {
                    number: i + 1,
                    indent,
                    continued,
                    spans,
                    collapsed: None,
                }
            })
            .collect();
        collapse_blank_runs(lines)
    }
}

fn is_blank(l: &DisplayLine) -> bool {
    l.spans.iter().all(|(_, s)| s.trim().is_empty())
}

fn collapse_blank_runs(lines: Vec<DisplayLine>) -> Vec<DisplayLine> {
    let mut out: Vec<DisplayLine> = Vec::with_capacity(lines.len());
    let mut run: Vec<DisplayLine> = Vec::new();
    let flush = |run: &mut Vec<DisplayLine>, out: &mut Vec<DisplayLine>| {
        if run.len() >= BLANK_RUN {
            out.push(DisplayLine {
                number: run[0].number,
                indent: 0,
                continued: false,
                spans: Vec::new(),
                collapsed: Some(run.len()),
            });
            run.clear();
        } else {
            out.append(run);
        }
    };
    for l in lines {
        if is_blank(&l) {
            run.push(l);
        } else {
            flush(&mut run, &mut out);
            out.push(l);
        }
    }
    flush(&mut run, &mut out);
    out
}

/// Colour of a section's invocation lines (`argv[i] ...`): readable, but
/// set apart from the content.
pub fn invocation_color(dark: bool) -> Color32 {
    if dark {
        Color32::from_rgb(150, 190, 230)
    } else {
        Color32::from_rgb(30, 80, 140)
    }
}

fn default_fg(dark: bool) -> Color32 {
    if dark {
        Color32::from_gray(220)
    } else {
        Color32::from_gray(30)
    }
}

pub const DANGER: Color32 = Color32::from_rgb(220, 50, 47);
/// Spaces in a row before they are shown as a marker instead.
const SPACE_RUN: usize = 12;
pub const WARN: Color32 = Color32::from_rgb(203, 120, 0);

/// Build the layout for one line, with the line number gutter.
pub fn layout(line: &DisplayLine, digits: usize, dark: bool, cont: char) -> LayoutJob {
    let font = FontId::monospace(13.0);
    let plain = |color: Color32| TextFormat {
        font_id: font.clone(),
        color,
        ..Default::default()
    };
    let dim = if dark {
        Color32::from_gray(110)
    } else {
        Color32::from_gray(150)
    };
    let mut job = LayoutJob::default();
    let number = line.number;
    let alert = |font: &FontId| TextFormat {
        font_id: font.clone(),
        color: Color32::WHITE,
        background: WARN,
        ..Default::default()
    };
    if let Some(n) = line.collapsed {
        job.append(&format!("{number:>digits$}   "), 0.0, plain(dim));
        job.append(&format!("⋯ {n} blank lines ⋯"), 0.0, alert(&font));
        return job;
    }
    let marker = if line.continued { cont } else { ' ' };
    job.append(&format!("{number:>digits$} {marker} "), 0.0, plain(dim));
    job.append(&"  ".repeat(line.indent), 0.0, plain(dim));
    for (color, text) in &line.spans {
        let mut run = String::new();
        let mut spaces = 0usize;
        let chars: Vec<char> = text.chars().collect();
        for (idx, &c) in chars.iter().enumerate() {
            // Long runs of spaces become a visible marker: whitespace must
            // not push code out of view.
            if c == ' ' {
                spaces += 1;
                if chars.get(idx + 1) == Some(&' ') {
                    continue;
                }
                if spaces >= SPACE_RUN {
                    if !run.is_empty() {
                        job.append(&std::mem::take(&mut run), 0.0, plain(*color));
                    }
                    job.append(&format!("⟨{spaces} spaces⟩"), 0.0, alert(&font));
                } else {
                    run.push_str(&" ".repeat(spaces));
                }
                spaces = 0;
                continue;
            }
            match classify(c) {
                None => run.push(c),
                Some(kind) => {
                    if !run.is_empty() {
                        job.append(&std::mem::take(&mut run), 0.0, plain(*color));
                    }
                    append_marked(&mut job, c, kind, &font);
                }
            }
        }
        if !run.is_empty() {
            job.append(&run, 0.0, plain(*color));
        }
    }
    job
}

fn append_marked(job: &mut LayoutJob, c: char, kind: FindingKind, font: &FontId) {
    match kind {
        FindingKind::NonAscii => job.append(
            &c.to_string(),
            0.0,
            TextFormat {
                font_id: font.clone(),
                color: WARN,
                underline: Stroke::new(1.5, WARN),
                ..Default::default()
            },
        ),
        _ => {
            let label = if kind == FindingKind::InvalidUtf8 {
                "⟨invalid⟩".to_string()
            } else {
                format!("⟨U+{:04X}⟩", c as u32)
            };
            job.append(
                &label,
                0.0,
                TextFormat {
                    font_id: font.clone(),
                    color: Color32::WHITE,
                    background: DANGER,
                    ..Default::default()
                },
            );
        }
    }
}
