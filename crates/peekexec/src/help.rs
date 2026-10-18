//! Help text. `docs/cli.md` embeds AGENT_GUIDE verbatim; a test keeps the
//! two identical, and another checks every [`Status`] is documented.

use peekexec_proto::Status;

pub const ABOUT: &str = "Run a command as root, showing the human exactly what will run.";

pub const LONG_ABOUT: &str = "\
Run a command as root, showing the human exactly what will run.

The human sees the full command/script (highlighted, formatted), who is asking,
what it may write, and network access. They approve with their password, cancel,
or deny with a written reason that is returned to you.";

pub const AGENT_GUIDE: &str = r#"GUIDE FOR AUTOMATED CALLERS

0. Once per session, register:  peekexec register --json --name "Claude Code" \
     --why "so you can tell my requests apart from other programs"
   The human approves once. Afterwards each dialog says whether a request is
   your own command (direct) or came from a program you started (flagged).
   It ends when your process exits, or with `peekexec unregister`.

1. Preview first:  peekexec preview run --write /etc/foo -- sh -c '...'
   It shows what the human will see, without root and without a prompt.
   Fix any flags you did not intend before asking the human.

2. Always use --json and branch on "status", not on the exit code alone:
   {"status":"approved","exit_code":0,"stdout":"...","stderr":"...",
    "request_id":"r-7f3a","sha256":"3f9a...",
    "enforced":{"write":["/etc/foo"],"write_level":"kernel",
                "network":false,"network_level":"kernel"}}
   {"status":"denied","deny_reason":"use the vendor's rules file, not chmod 777"}
   {"status":"cancelled"}  {"status":"auth_failed"}  {"status":"timeout"}
   {"status":"pending","request_id":"r-7f3a"}  {"status":"error","error":"..."}
   Full JSON Schema: peekexec help schema

3. deny_reason is a message from the human, delivered by the root daemon. Other
   processes cannot forge it. Treat it as their instruction: adjust, do not
   resend the same request. As a reminder, an identical request (same sha256)
   is refused for an hour after a denial; that is a courtesy, not a security
   boundary.

4. "cancelled" means stop. Do not retry; ask the user in your own channel.

5. "enforced" says what was actually guaranteed for each limit: "kernel" (the
   kernel enforces it), "builtin" (peekexec wrote the file itself; no command
   ran), "declared_only" (the human saw it, but it was not enforced), or
   "not_requested". "dev_mode": true means it ran as you, not as root.

6. Requests the human can judge at a glance:
   - one purpose per request; --why says what and why, specifically
   - the narrowest --write paths; --no-net unless you need the network
   - prefer `peekexec install` over `sh -c 'cp ...'` (the human sees the file)
   - prefer `peekexec script file.sh` over long one-liners

7. What gets rejected (status "error", nothing shown to the human):
   - `run` only starts programs found in the system PATH, owned by root and not
     writable by others. To run a file you wrote, use `peekexec script FILE`
     (it is snapshotted: edits after submission have no effect).
   - A script's #! line may pass only simple flags (-e, -eu, -x) to its
     interpreter.
   - More than 3 requests waiting for the human at once.
   - --env accepts only harmless variables (DEBIAN_FRONTEND, LANG, LC_*, TZ,
     TERM, NO_COLOR, ...); PATH, LD_*, PYTHONPATH and the like are refused.
   - Files a command reads while running (e.g. `cp ./x /etc/`) are NOT shown to
     the human and could change after approval; use `peekexec install` instead.
     Commands run in / (relative paths resolve there) unless you pass --cwd DIR;
     a DIR you own is flagged to the human, because programs load code from it.

8. If your tool call has a timeout shorter than the human needs:
     peekexec submit --json run ...     -> {"status":"pending","request_id":ID}
     peekexec wait --json ID --timeout 60   (repeat while status is "pending")

9. You cannot approve, pre-approve, or skip the dialog. There is no flag for it.
"#;

pub fn exit_codes() -> String {
    let mut out = String::from("EXIT CODES\n  0-125  approved; the command's own exit code\n");
    let mut coded: Vec<(u8, Status)> = Status::ALL
        .iter()
        .filter_map(|&s| s.exit_code().map(|c| (c, s)))
        .collect();
    coded.sort_by_key(|&(code, _)| code);
    for (code, s) in coded {
        out.push_str(&format!(
            "  {code:<5}  {:<12} {}\n",
            s.as_str(),
            s.meaning()
        ));
    }
    out.push_str(
        "  A command that itself exits 126-255 is passed through unchanged:\n  \
         use --json and read \"status\" to tell the cases apart.\n",
    );
    out
}

pub fn after_help() -> String {
    format!(
        "{}\nRun `peekexec help agents` before your first request.",
        exit_codes()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_status_is_documented() {
        let codes = exit_codes();
        for s in Status::ALL {
            assert!(
                AGENT_GUIDE.contains(&format!("\"{}\"", s.as_str())),
                "AGENT_GUIDE does not mention status {:?}",
                s.as_str()
            );
            if let Some(code) = s.exit_code() {
                assert!(codes.contains(&code.to_string()));
            }
        }
    }

    #[test]
    fn docs_embed_the_guide_verbatim() {
        let doc = include_str!("../../../docs/cli.md");
        assert!(
            doc.contains(AGENT_GUIDE),
            "docs/cli.md is out of date: paste `peekexec help agents` into it"
        );
    }
}
