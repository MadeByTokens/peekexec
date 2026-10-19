//! Helpers that turn a request into text for the human. Display only:
//! nothing here may influence what executes.

/// Join argv the way a POSIX shell would need it typed, quoting only
/// where necessary.
pub fn shell_join(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Control characters (newline, tab, ...) are written as `$'…'` escapes,
/// so one argument always stays on one line and cannot pass for several.
pub fn shell_quote(arg: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        arg.to_string()
    } else if arg.chars().any(char::is_control) {
        let mut out = String::from("$'");
        for c in arg.chars() {
            match c {
                '\\' => out.push_str(r"\\"),
                '\'' => out.push_str(r"\'"),
                '\n' => out.push_str(r"\n"),
                '\t' => out.push_str(r"\t"),
                '\r' => out.push_str(r"\r"),
                c if c.is_control() && (c as u32) < 0x80 => {
                    out.push_str(&format!(r"\x{:02x}", c as u32))
                }
                c if c.is_control() => out.push_str(&format!(r"\u{:04x}", c as u32)),
                c => out.push(c),
            }
        }
        out.push('\'');
        out
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_only_when_needed() {
        let argv = ["sh", "-c", "echo 'hi' && ls", ""].map(String::from);
        assert_eq!(shell_join(&argv), r"sh -c 'echo '\''hi'\'' && ls' ''");
    }

    #[test]
    fn control_characters_never_break_the_line() {
        let argv = ["chmod", "0755", "/a\nargv[3] /b", "x\ty", "it's\\"].map(String::from);
        let s = shell_join(&argv);
        assert!(!s.contains('\n') && !s.contains('\t'), "{s}");
        assert_eq!(s, r"chmod 0755 $'/a\nargv[3] /b' $'x\ty' 'it'\''s\'");
        assert_eq!(shell_quote("a'\n\\"), r"$'a\'\n\\'");
        assert_eq!(shell_quote("\u{1b}[31m"), r"$'\x1b[31m'");
    }
}
