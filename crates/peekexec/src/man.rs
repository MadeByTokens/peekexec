//! The man page, `peekexec help man`.
//!
//! Prose lives in `manual.md`, the one file to edit by hand. What can be
//! read from the code is: commands, options, exit codes, JSON fields and the
//! agent guide are generated here, so they cannot go stale. The page shipped
//! is `packaging/man/peekexec.1`, written from this by
//! `scripts/gen-cli-doc.sh`; a test fails if it differs, or if the prose
//! names an option that does not exist.
//!
//! `manual.md` is a small subset of Markdown: `#` and `##` headings, blank
//! lines between paragraphs, `- ` lists, ``` blocks, `code`, **bold**, and
//! `@name` lines for the generated parts.

use clap::{Arg, Command};

use peekexec_proto::Status;

use crate::help;

const MANUAL: &str = include_str!("manual.md");

/// Text with roff's special characters made plain.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\\' => out.push_str("\\e"),
            '-' => out.push_str("\\-"),
            // By code point: not every groff is set up to read UTF-8.
            c if !c.is_ascii() => out.push_str(&format!("\\[u{:04X}]", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// A line that cannot be read as a roff request.
fn guarded(line: String) -> String {
    if line.starts_with(['.', '\'']) {
        format!("\\&{line}")
    } else {
        line
    }
}

/// `code` and **bold** in bold, the rest plain.
fn inline(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(i) = rest.find(['`', '*']) {
        let mark = if rest[i..].starts_with("**") {
            "**"
        } else if rest[i..].starts_with('`') {
            "`"
        } else {
            out.push_str(&escape(&rest[..=i]));
            rest = &rest[i + 1..];
            continue;
        };
        let body = &rest[i + mark.len()..];
        let Some(end) = body.find(mark) else {
            break;
        };
        out.push_str(&escape(&rest[..i]));
        out.push_str(&format!("\\fB{}\\fR", escape(&body[..end])));
        rest = &body[end + mark.len()..];
    }
    out.push_str(&escape(rest));
    guarded(out)
}

fn preformatted(text: &str) -> String {
    let mut out = String::from(".RS 4\n.nf\n");
    for line in text.lines() {
        out.push_str(&guarded(escape(line)));
        out.push('\n');
    }
    out.push_str(".fi\n.RE\n");
    out
}

fn headings() -> Vec<&'static str> {
    MANUAL
        .lines()
        .filter_map(|l| l.strip_prefix("# "))
        .filter(|h| !matches!(*h, "NAME" | "SYNOPSIS" | "DESCRIPTION"))
        .collect()
}

fn argument(arg: &Arg) -> String {
    let mut name = String::new();
    if let Some(short) = arg.get_short() {
        name.push_str(&format!("\\fB\\-{short}\\fR, "));
    }
    let values = arg
        .get_value_names()
        .map(|v| v.iter().map(|s| s.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    match arg.get_long() {
        Some(long) => name.push_str(&format!("\\fB{}\\fR", escape(&format!("--{long}")))),
        None if values.is_empty() => name.push_str(arg.get_id().as_str()),
        None => name.push_str(&escape(&values.join(" "))),
    }
    let takes_value = arg.get_action().takes_values();
    if arg.get_long().is_some() && takes_value {
        let value = if values.is_empty() {
            arg.get_id().as_str().to_uppercase()
        } else {
            values.join(" ")
        };
        name.push_str(&format!(" \\fI{}\\fR", escape(&value)));
    }
    let mut about = arg
        .get_long_help()
        .or(arg.get_help())
        .map(|h| h.to_string())
        .unwrap_or_default();
    let defaults: Vec<String> = arg
        .get_default_values()
        .iter()
        .map(|v| v.to_string_lossy().into_owned())
        .collect();
    if !defaults.is_empty() && takes_value {
        about.push_str(&format!(" (default: {})", defaults.join(" ")));
    }
    format!(".TP\n{name}\n{}\n", guarded(escape(about.trim())))
}

/// `Usage: x y` as `x y`, with the program's full name.
fn usage(cmd: &Command, path: &str) -> String {
    let text = cmd.clone().bin_name(path).render_usage().to_string();
    text.trim_start_matches("Usage: ").trim().to_string()
}

fn command(cmd: &Command, path: &str, shared: &[String]) -> String {
    let mut out = format!(".SS \"{}\"\n", escape(path));
    out.push_str(&format!("\\fB{}\\fR\n.br\n", escape(&usage(cmd, path))));
    if let Some(about) = cmd.get_long_about().or(cmd.get_about()) {
        out.push_str(&format!("{}\n", guarded(escape(&about.to_string()))));
    }
    let args = cmd.get_arguments().filter(|a| {
        let id = a.get_id().as_str();
        !a.is_global_set()
            && !a.is_positional()
            && !matches!(id, "help" | "version")
            && !shared.iter().any(|s| s == id)
    });
    args.for_each(|a| out.push_str(&argument(a)));
    out
}

/// Options `run`, `script` and `install` all take: on the page once.
fn shared_options(root: &Command) -> Vec<&Arg> {
    let of = |name: &str| root.find_subcommand(name).expect("a command");
    let first = of("run");
    first
        .get_arguments()
        .filter(|a| {
            !a.is_global_set()
                && !a.is_positional()
                && !matches!(a.get_id().as_str(), "help" | "version")
                && ["script", "install"]
                    .iter()
                    .all(|c| of(c).get_arguments().any(|b| b.get_id() == a.get_id()))
        })
        .collect()
}

/// Every command but `help`, which the synopsis covers.
fn commands(root: &Command) -> String {
    let shared_args = shared_options(root);
    let shared: Vec<String> = shared_args.iter().map(|a| a.get_id().to_string()).collect();
    let mut out = String::new();
    for cmd in root.get_subcommands().filter(|c| c.get_name() != "help") {
        out.push_str(&command(
            cmd,
            &format!("peekexec {}", cmd.get_name()),
            &shared,
        ));
    }
    out.push_str(".SS \"Options of run, script and install\"\n");
    out.push_str("These also apply through preview and submit.\n");
    shared_args.iter().for_each(|a| out.push_str(&argument(a)));
    out
}

fn global_options(root: &Command) -> String {
    root.get_arguments()
        .filter(|a| !matches!(a.get_id().as_str(), "version"))
        .map(argument)
        .collect()
}

/// One entry per status, from the code that gives them.
fn exit_status() -> String {
    let mut out = String::from(".TP\n\\fB0\\-125\\fR\napproved; the command's own exit code\n");
    let mut coded: Vec<(u8, Status)> = Status::ALL
        .iter()
        .filter_map(|&s| s.exit_code().map(|c| (c, s)))
        .collect();
    coded.sort_by_key(|&(code, _)| code);
    for (code, s) in coded {
        out.push_str(&format!(
            ".TP\n\\fB{code}\\fR  {}\n{}\n",
            escape(s.as_str()),
            guarded(escape(s.meaning()))
        ));
    }
    out.push_str(
        ".PP\nA command that itself exits 126\\-255 is passed through unchanged: use \
         \\fB\\-\\-json\\fR and read \\fBstatus\\fR to tell the cases apart.\n",
    );
    out
}

/// The fields of `--json` output and their documentation, from the schema.
fn json_fields() -> Vec<(String, String)> {
    let schema = serde_json::to_value(schemars::schema_for!(peekexec_proto::Response))
        .expect("the schema serializes");
    schema["properties"]
        .as_object()
        .expect("an object")
        .iter()
        .map(|(name, field)| {
            let about = field["description"].as_str().unwrap_or("");
            let about = about.split_whitespace().collect::<Vec<_>>().join(" ");
            (name.clone(), about)
        })
        .collect()
}

fn json_section() -> String {
    json_fields()
        .iter()
        .map(|(name, about)| format!(".TP\n\\fB{}\\fR\n{}\n", escape(name), inline(about)))
        .collect()
}

pub fn render(root: &Command) -> String {
    let mut out = format!(
        ".\\\" Generated by `peekexec help man`: edit crates/peekexec/src/manual.md.\n\
         .TH PEEKEXEC 1 \"\" \"peekexec {}\" \"User Commands\"\n\
         .\\\" No hyphenation or justification: a word split over two lines\n\
         .\\\" cannot be found with the pager's search.\n\
         .nh\n\
         .ad l\n",
        env!("CARGO_PKG_VERSION")
    );
    let mut block: Option<String> = None;
    for line in MANUAL.lines() {
        if line == "```" {
            match block.take() {
                Some(text) => out.push_str(&preformatted(&text)),
                None => block = Some(String::new()),
            }
        } else if let Some(text) = &mut block {
            text.push_str(line);
            text.push('\n');
        } else if let Some(heading) = line.strip_prefix("# ") {
            out.push_str(&format!(".SH \"{}\"\n", escape(heading)));
        } else if let Some(heading) = line.strip_prefix("## ") {
            let heading = heading.replace('"', "\\(dq");
            out.push_str(&format!(
                ".SS \"{}\"\n",
                escape(&heading).replace("\\e(dq", "\\(dq")
            ));
        } else if let Some(item) = line.strip_prefix("- ") {
            out.push_str(&format!(".IP \\(bu 2\n{}\n", inline(item)));
        } else if line.is_empty() {
            out.push_str(".PP\n");
        } else {
            match line {
                "@contents" => {
                    let list = headings().join("\n");
                    out.push_str(&format!(".PP\nSections:\n{}", preformatted(&list)));
                }
                "@commands" => out.push_str(&commands(root)),
                "@global-options" => out.push_str(&global_options(root)),
                "@exit-codes" => out.push_str(&exit_status()),
                "@json-fields" => out.push_str(&json_section()),
                "@agents" => out.push_str(&preformatted(help::AGENT_GUIDE)),
                other => {
                    assert!(!other.starts_with('@'), "unknown part {other}");
                    out.push_str(&inline(other));
                    out.push('\n');
                }
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    fn page() -> String {
        render(&crate::Cli::command())
    }

    #[test]
    fn the_shipped_page_is_current() {
        assert_eq!(
            include_str!("../../../packaging/man/peekexec.1"),
            page(),
            "packaging/man/peekexec.1 is out of date: run scripts/gen-cli-doc.sh"
        );
    }

    /// The prose is written by hand: an option it names must still exist.
    #[test]
    fn the_prose_names_only_options_that_exist() {
        fn options(cmd: &Command, out: &mut Vec<String>) {
            out.extend(
                cmd.get_arguments()
                    .filter_map(|a| a.get_long())
                    .map(String::from),
            );
            cmd.get_subcommands().for_each(|c| options(c, out));
        }
        let mut known = Vec::new();
        options(&crate::Cli::command(), &mut known);
        // The daemon's, the installer's, and options of other programs.
        let elsewhere = [
            "allow-unverified-display",
            "prompt-lines",
            "dev",
            "admin-group",
            "uninstall",
            "release",
            "locked",
            "reload-rules",
        ];
        for word in MANUAL.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
            if let Some(name) = word.strip_prefix("--").filter(|n| !n.is_empty()) {
                assert!(
                    known.iter().any(|k| k == name) || elsewhere.contains(&name),
                    "manual.md names --{name}, which does not exist"
                );
            }
        }
    }

    #[test]
    fn everything_is_on_the_page() {
        let page = page();
        for cmd in crate::Cli::command().get_subcommands() {
            if cmd.get_name() != "help" {
                let name = format!("peekexec {}", cmd.get_name());
                assert!(page.contains(&format!(".SS \"{name}\"")), "{name}");
            }
        }
        for s in peekexec_proto::Status::ALL {
            assert!(page.contains(&escape(s.as_str())), "{s:?}");
        }
        assert!(page.contains(&escape("--write")));
        assert!(page.contains("GUIDE FOR AUTOMATED CALLERS"));
    }

    #[test]
    fn every_json_field_is_explained() {
        for (name, about) in json_fields() {
            assert!(!about.is_empty(), "Response.{name} has no doc comment");
        }
    }

    #[test]
    fn text_cannot_become_a_roff_request() {
        assert_eq!(inline(".SH x"), "\\&.SH x");
        assert_eq!(inline("a `b-c` **d**"), "a \\fBb\\-c\\fR \\fBd\\fR");
        assert_eq!(escape("a\\b"), "a\\eb");
    }
}
