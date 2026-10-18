//! Finds characters that can make text look different from what it does:
//! control characters, bidi overrides ("Trojan Source"), invisible
//! characters, and non-ASCII (possible look-alikes). The dialog marks each
//! finding in red; it never hides or rewrites them.

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    ControlChar,
    BidiControl,
    Invisible,
    InvalidUtf8,
    NonAscii,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    /// 1-based line number.
    pub line: usize,
    /// 1-based column, counted in characters.
    pub column: usize,
    /// The character as `U+XXXX`.
    pub codepoint: String,
    pub kind: FindingKind,
}

pub fn classify(c: char) -> Option<FindingKind> {
    match c {
        '\n' | '\t' => None,
        '\u{FFFD}' => Some(FindingKind::InvalidUtf8),
        // Line and paragraph separators break lines in many renderers.
        '\u{2028}' | '\u{2029}' => Some(FindingKind::ControlChar),
        '\u{061C}'
        | '\u{200E}'
        | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}' => Some(FindingKind::BidiControl),
        '\u{00AD}'
        | '\u{180E}'
        | '\u{200B}'..='\u{200D}'
        | '\u{2060}'..='\u{2064}'
        | '\u{FEFF}' => Some(FindingKind::Invisible),
        c if c.is_control() => Some(FindingKind::ControlChar),
        c if !c.is_ascii() => Some(FindingKind::NonAscii),
        _ => None,
    }
}

pub fn scan(text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (line_idx, line) in text.split('\n').enumerate() {
        for (col_idx, c) in line.chars().enumerate() {
            if let Some(kind) = classify(c) {
                findings.push(Finding {
                    line: line_idx + 1,
                    column: col_idx + 1,
                    codepoint: format!("U+{:04X}", c as u32),
                    kind,
                });
            }
        }
    }
    findings
}

/// Like [`scan`], for file contents that may not be valid UTF-8. Invalid
/// sequences are reported as [`FindingKind::InvalidUtf8`].
pub fn scan_bytes(bytes: &[u8]) -> Vec<Finding> {
    scan(&String::from_utf8_lossy(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(text: &str) -> Vec<FindingKind> {
        scan(text).into_iter().map(|f| f.kind).collect()
    }

    #[test]
    fn plain_shell_is_clean() {
        assert!(scan("cp a b && \\\n\tudevadm trigger\n").is_empty());
    }

    #[test]
    fn flags_trojan_source() {
        let f = scan("echo ok\nrm -rf /tmp/x \u{202E}gnp.");
        assert_eq!(f.len(), 1);
        assert_eq!((f[0].line, f[0].column), (2, 15));
        assert_eq!(f[0].kind, FindingKind::BidiControl);
        assert_eq!(f[0].codepoint, "U+202E");
    }

    #[test]
    fn flags_each_kind() {
        assert_eq!(
            kinds("a\rb\u{200B}c\u{0441}"),
            [
                FindingKind::ControlChar,
                FindingKind::Invisible,
                FindingKind::NonAscii
            ]
        );
    }

    #[test]
    fn flags_line_separators() {
        assert_eq!(
            kinds("a\u{2028}b\u{2029}c"),
            [FindingKind::ControlChar, FindingKind::ControlChar]
        );
    }

    #[test]
    fn flags_invalid_utf8() {
        let f = scan_bytes(b"echo \xff\n");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].kind, FindingKind::InvalidUtf8);
    }
}
