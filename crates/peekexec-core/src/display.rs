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

pub fn shell_quote(arg: &str) -> String {
    let safe = |c: char| c.is_ascii_alphanumeric() || "_@%+=:,./-".contains(c);
    if !arg.is_empty() && arg.chars().all(safe) {
        arg.to_string()
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
}
