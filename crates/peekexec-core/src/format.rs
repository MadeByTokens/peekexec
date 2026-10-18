//! Display-only layout of a shell one-liner (`sh -c '...'`).
//!
//! The guarantee is structural: every [`Line`] is an exact, contiguous slice
//! of the original, in order, so joining the slices reproduces the original
//! byte for byte ([`format_shell`] checks this and falls back to one line per
//! original line if it ever fails). Breaks and indentation are added only
//! for the eye; nothing is reworded. The lexer only chooses *where* to
//! break; a lexer mistake can make the layout ugly, never wrong.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Line {
    /// Exact slice of the original (including any surrounding whitespace).
    pub text: String,
    /// Display indentation level.
    pub indent: usize,
    /// True if this line was split off the previous one for display only
    /// (the original has no newline here).
    pub continued: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tok {
    Word,
    /// `;` or `&`
    Sep,
    /// `&&`, `||`, `|`
    Chain,
    Newline,
    Comment,
    Other,
}

/// Top-level tokens as (kind, start, end) byte spans. Quotes, `$(...)`,
/// `${...}`, backticks and backslash escapes are kept inside words.
fn tokenize(s: &str) -> Vec<(Tok, usize, usize)> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        match c {
            b' ' | b'\t' => i += 1,
            b'\n' => {
                out.push((Tok::Newline, i, i + 1));
                i += 1;
            }
            b'#' => {
                let end = s[i..].find('\n').map_or(b.len(), |n| i + n);
                out.push((Tok::Comment, i, end));
                i = end;
            }
            // Redirections, not separators: `>&2`, `<&3`, `&>file`, `>|file`.
            b'&' | b'|' if i > 0 && matches!(b[i - 1], b'>' | b'<') => {
                out.push((Tok::Other, i, i + 1));
                i += 1;
            }
            b'&' if b.get(i + 1) == Some(&b'>') => {
                out.push((Tok::Other, i, i + 1));
                i += 1;
            }
            b'&' | b'|' => {
                let double = b.get(i + 1) == Some(&c);
                let kind = if double || c == b'|' {
                    Tok::Chain
                } else {
                    Tok::Sep
                };
                let len = if double { 2 } else { 1 };
                out.push((kind, i, i + len));
                i += len;
            }
            b';' => {
                let len = if b.get(i + 1) == Some(&b';') { 2 } else { 1 };
                let kind = if len == 2 { Tok::Other } else { Tok::Sep };
                out.push((kind, i, i + len));
                i += len;
            }
            b'(' | b')' | b'<' | b'>' => {
                out.push((Tok::Other, i, i + 1));
                i += 1;
            }
            _ => {
                let start = i;
                i = word_end(b, i);
                out.push((Tok::Word, start, i));
            }
        }
    }
    out
}

fn word_end(b: &[u8], mut i: usize) -> usize {
    let mut depth = 0usize; // inside $( ... ) / ${ ... }
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'\'' if depth == 0 => {
                i += 1;
                while i < b.len() && b[i] != b'\'' {
                    i += 1;
                }
                i += 1;
            }
            b'"' => {
                i += 1;
                while i < b.len() && b[i] != b'"' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'`' => {
                i += 1;
                while i < b.len() && b[i] != b'`' {
                    i += if b[i] == b'\\' { 2 } else { 1 };
                }
                i += 1;
            }
            b'$' if matches!(b.get(i + 1), Some(b'(' | b'{')) => {
                depth += 1;
                i += 2;
            }
            b'(' | b'{' if depth > 0 => {
                depth += 1;
                i += 1;
            }
            b')' | b'}' if depth > 0 => {
                depth -= 1;
                i += 1;
            }
            b' ' | b'\t' | b'\n' | b';' | b'&' | b'|' | b'(' | b')' | b'<' | b'>' if depth == 0 => {
                break
            }
            _ => i += 1,
        }
    }
    i.min(b.len())
}

const OPENERS: &[&str] = &["then", "do", "else", "{"];
const CLOSERS: &[&str] = &["fi", "done", "esac", "}", "else", "elif"];

/// Lay out a shell script for display. See the module docs for the guarantee.
pub fn format_shell(script: &str) -> Vec<Line> {
    let lines = layout(script);
    let rejoined: String = lines.iter().map(|l| l.text.as_str()).collect();
    if rejoined == script {
        lines
    } else {
        verbatim(script)
    }
}

/// One display line per original line, unindented.
pub fn verbatim(text: &str) -> Vec<Line> {
    text.split_inclusive('\n')
        .map(|t| Line {
            text: t.to_string(),
            indent: 0,
            continued: false,
        })
        .collect()
}

fn layout(s: &str) -> Vec<Line> {
    let toks = tokenize(s);
    let mut lines = Vec::new();
    let mut depth = 0usize;
    let mut line_start = 0usize;
    let mut line_indent = 0usize;
    let mut continued = false;
    // Whether the next word is in command position (keywords only count there).
    let mut command_pos = true;
    // Whether the current line continues a chained command (&&, ||, |).
    let mut in_chain = false;

    let word = |t: &(Tok, usize, usize)| &s[t.1..t.2];

    for (idx, tok) in toks.iter().enumerate() {
        let next = toks.get(idx + 1);
        // `if x; then` and `for x; do` stay on one line.
        let next_joins = next.is_some_and(|n| n.0 == Tok::Word && matches!(word(n), "then" | "do"));
        let mut break_after = false;
        match tok.0 {
            Tok::Word => {
                let w = word(tok);
                let keyword = command_pos;
                if keyword && CLOSERS.contains(&w) && tok.1 == first_tok_start(&toks, line_start) {
                    depth = depth.saturating_sub(1);
                    line_indent = depth;
                }
                if keyword && OPENERS.contains(&w) {
                    depth += 1;
                    break_after = true;
                    in_chain = false;
                }
                command_pos = keyword && matches!(w, "if" | "while" | "until" | "!" | "elif");
                if keyword && OPENERS.contains(&w) {
                    command_pos = true;
                }
            }
            Tok::Sep => {
                command_pos = true;
                in_chain = false;
                break_after = !next_joins;
            }
            Tok::Chain => {
                command_pos = true;
                in_chain = true;
                break_after = true;
            }
            Tok::Newline => {
                command_pos = true;
                // The original's own newline ends the line (it is part of the slice).
                lines.push(Line {
                    text: s[line_start..tok.2].to_string(),
                    indent: line_indent,
                    continued,
                });
                line_start = tok.2;
                continued = false;
                line_indent = depth + usize::from(in_chain);
                continue;
            }
            Tok::Comment | Tok::Other => {}
        }
        if break_after && next.is_some_and(|n| n.0 != Tok::Newline && n.0 != Tok::Comment) {
            lines.push(Line {
                text: s[line_start..tok.2].to_string(),
                indent: line_indent,
                continued,
            });
            line_start = tok.2;
            continued = true;
            line_indent = depth + usize::from(in_chain);
        }
    }
    if line_start < s.len() || lines.is_empty() {
        lines.push(Line {
            text: s[line_start..].to_string(),
            indent: line_indent,
            continued,
        });
    }
    lines
}

/// Start of the first token at or after `pos` (where a line's text begins).
fn first_tok_start(toks: &[(Tok, usize, usize)], pos: usize) -> usize {
    toks.iter().find(|t| t.1 >= pos).map_or(pos, |t| t.1)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shown(script: &str) -> Vec<String> {
        format_shell(script)
            .iter()
            .map(|l| format!("{}{}", "  ".repeat(l.indent), l.text.trim()))
            .collect()
    }

    #[test]
    fn chains_break_and_indent() {
        assert_eq!(
            shown("cp a /etc/x/ && udevadm control --reload-rules && udevadm trigger"),
            [
                "cp a /etc/x/ &&",
                "  udevadm control --reload-rules &&",
                "  udevadm trigger"
            ]
        );
    }

    #[test]
    fn blocks_indent() {
        assert_eq!(
            shown("if [ -f x ]; then cp x y; rm x; else echo no; fi; echo done"),
            [
                "if [ -f x ]; then",
                "  cp x y;",
                "  rm x;",
                "else",
                "  echo no;",
                "fi;",
                "echo done"
            ]
        );
        assert_eq!(
            shown("for f in *.rules; do cp \"$f\" /etc/; done"),
            ["for f in *.rules; do", "  cp \"$f\" /etc/;", "done"]
        );
    }

    #[test]
    fn redirections_are_not_separators() {
        assert_eq!(
            shown("echo missing >&2; exit 1"),
            ["echo missing >&2;", "exit 1"]
        );
        assert_eq!(
            shown("cmd &>/dev/null || cmd 2>&1 >|f"),
            ["cmd &>/dev/null ||", "  cmd 2>&1 >|f"]
        );
    }

    #[test]
    fn quotes_and_substitutions_are_not_split() {
        assert_eq!(
            shown("echo 'a && b; c' \"x | y\" $(ls; pwd) `id; id` ${v:-a;b}"),
            ["echo 'a && b; c' \"x | y\" $(ls; pwd) `id; id` ${v:-a;b}"]
        );
    }

    #[test]
    fn original_newlines_are_kept_and_not_marked() {
        let lines = format_shell("echo a\necho b && echo c\n");
        assert!(!lines[1].continued);
        assert!(lines[2].continued);
    }

    #[test]
    fn always_reconstructs_the_original() {
        let nasty = [
            "",
            "id",
            "a&&b||c|d;e&f",
            "echo 'unterminated && x",
            "echo \"unterminated $(x; y",
            "echo \\; rm -rf / \\&\\& x",
            "case $x in a) echo 1;; b) echo 2;; esac",
            "  leading;  trailing  ;  ",
            "x=$(( 1 + 2 )); { a; b; }; (c; d)",
            "echo é\u{202E}x && y # comment; with && ops\nz",
            ";;;&&&|||",
        ];
        for s in nasty {
            let rejoined: String = format_shell(s).iter().map(|l| l.text.as_str()).collect();
            assert_eq!(rejoined, s, "for {s:?}");
        }
    }

    #[test]
    fn random_input_never_panics_or_changes_bytes() {
        let alphabet: Vec<char> = "ab &|;'\"$(){}`\\#\n\té\u{202E}<>".chars().collect();
        let mut seed: u64 = 0x9e3779b97f4a7c15;
        for _ in 0..20_000 {
            let mut s = String::new();
            seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            for _ in 0..(seed >> 59) as usize + 1 {
                seed = seed
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                s.push(alphabet[(seed >> 33) as usize % alphabet.len()]);
            }
            let lines = layout(&s);
            let rejoined: String = lines.iter().map(|l| l.text.as_str()).collect();
            assert_eq!(rejoined, s, "layout changed {s:?}");
        }
    }
}
