# Fifth review (2026-10-31, commit f617b73)

Review only: no code changed. Six reviewers by area, one verifier of the 20
commits after dce4e51, one verifier of the findings, then live checks.

**Result.** No path was found that runs a request without a human, or gives a
non-administrator root, and no way for an approval to attach to another
request. One finding breaks "what is shown is what runs" in the default view
of the dialog; two more break it under conditions a requester can arrange.

Failing tests: `fifth-review-tests/finding-tests.patch` and
`recent-commits-tests.patch` (apply to f617b73). They fail until fixed.
`recent-commits-tests.patch` also extracts `walk()` in `peer.rs` so /proc reads
can be scripted, and has a throwaway `zz_dump_classes` test.

Evidence words: **run** = a test or live check failed as described; **read** =
confirmed by reading the code only.

## Live checks

| Check | Result |
|---|---|
| CI commands locally (fmt, clippy, shellcheck, docs, deny, audit, tests) | pass |
| Installed client vs a build of HEAD | byte-identical; daemon and dialog match in size only (not hashed: 0711) |
| `unsafe` counts vs SECURITY.md | match in all nine files |
| `dev/wayland-vm/approve-test.sh --install` on HEAD (GNOME 46, polkit 124) | 5 of 5 pass |
| Random-input harness (stable Rust, 10 min) | no panic in 66,180,776 cases, 18,673,490 of them valid messages; `Shown` kept its no-line-break, no-control-character rule; many shell inputs gave a `Line` with an interior newline (finding 1) |
| 2x text scale, real GNOME prompt | finding 2 |
| User drop-in on the shell's unit | finding 3 |

## Critical

**1. Formatted view drops newlines inside a word** (run, screenshot).
`format_shell` keeps `$(...)`, quotes and backticks as one `Line`, with interior
newlines; syntect is given it as one line, and `code.rs:84-87` trims and filters
the newline-only spans. `cp $(echo /tmp/ok<LF>rm -rf /srv/data) /etc/x` is drawn
as one line, `cp $(echo /tmp/okrm -rf /srv/data) /etc/x`, tab "1 line". A quoted
string of 200 newlines also defeats blank-line collapsing and pushes the
real command out of view with no marker. `sh -c` only; Raw and the desktop
prompt are correct; a click is required. Tests pin the formatter's slices, not
what is drawn. Fix: a `Line` never holds a newline (split after layout, in the
property test too); the highlighter asserts its spans rejoin to the text.

## High

**2. The "fits in 22 lines" guarantee does not hold** (run, VM). With
`text-scaling-factor` 2.0, a plain dconf key for the same user, an 8-line script
well inside the limit pushed the password field and buttons off screen and began
clipping the message. Typing the password and Enter blind still approved. No
requester is needed on a smaller logical screen (2560x1440 at 200% is 720 px).
The prompt is the only trusted view on this path. Fix: stop relying on fit; end
the message with a fixed sentinel ("N lines; if you do not see END, cancel"), and
read scale and height as the user and refuse when not nominal.

**3. Tier 2 proves the shell's file, not its code** (partly run, VM). A marker
in a user drop-in on `org.gnome.Shell@wayland.service` reached the running
shell's environment after a reboot, and peekexec still used the polkit path
without noticing. Extensions come from `$HOME`, and `LD_PRELOAD` would take the
same route as the marker (neither run). So a requester that writes `$HOME` and
survives a re-login could run code in the process that draws the prompt.
The verifier rated this medium (needs a re-login); I keep it high because it
removes tier 2's guarantee silently. Fix: state the limit in THREAT_MODEL; refuse
on executable mappings outside root-controlled paths; the class only goes away
with a prompt outside the session (E12).

**4. Working directory shown can differ from the one entered** (run for verify;
the race itself read only). `open_workdir` canonicalizes then opens by name;
`verify` compares with `metadata()`, which follows the same link, and passes a
symlink at the last component and in the middle. A swap in that window shows
`/home/u/a` with no warning and enters a root-controlled directory. Verifier:
medium-high. Fix: compare `readlink(/proc/self/fd/N)` with the shown path.

## Medium

5. **Reply larger than `MAX_MSG` after the command ran** (run). 6,000,000 NUL
   bytes on stdout become about 36 MB of JSON; the client says "cannot reach
   peekexecd", exit code and output are lost, `wait` fails the same way, and the
   agent may rerun a non-idempotent command. Two reviewers found it apart.
6. **Any trusted program can be a `#!` interpreter** (run). Flagless `make`,
   `sed`, `awk`, `tar`, `git`, `vim`, `find`, `rsync` are accepted; `sed` gets
   script args with no `--`. The checklist's claim about make was false.
7. **Enter-to-approve is a denylist the requester can test** (run). `prlimit`,
   `setarch`, `logsave`, `ip netns exec`, `sg`, `dpkg -i` and others are eligible,
   as are 5000 arguments, and preview returns the bit. Verifier: low-medium, since
   the password is still typed. It breaks "denylists only warn", which is why
   8 matters. Fix: remove Enter approval, or use an allowlist of inert programs.
8. **Lasting-root and path notes miss common forms** (run). `chmod 5755/3755`
   (`setuid_mode` tests 2, 4, 6, 7 only), `usermod -aGdocker`, `--groups=`,
   `install --mode=4755`, `-Dm4755` are unflagged and Enter-eligible; `if`/`while`
   prefixes and backslash-newline lose the note. `-xzf/home/u/x.tar` and
   `--config=rel/path` get no path note (read).
9. **Comparison with the previous request** (run). A request cancelled before any
   dialog becomes "the request you saw" and overwrites the real baseline; "half"
   is about a quarter (edits count twice); argv and args boundaries and invalid
   bytes compare equal. Fix: remember only on a shown dialog, compare by digest.
10. **Request table not bounded** (run). 200 refused Submits with a 1 MiB path grew
    the daemon from 7 MB to 220 MB; `lookup` ignores expiry, so root output can
    stay readable by id past 15 minutes. OOM would end running commands.
11. **Dialog facts can be pushed out of view** (read, screenshots). An unbounded
    `--write` list and long process chains sit above the warnings in a header
    that scrolls by itself; long titles push the Raw toggle off the window.
12. **Audit can be rotated out** (read). No rate limit plus no bound on refused
    requests means a flood can vacuum older lines. Medium confidence.

## Low

- Ancestry walk: a reused pid can still join the chain (648e2ab, run); read ppid
  and start time in one read and compare.
- Client: daemon text reaches the terminal raw on `preview`, and the socket path
  in the warning is unescaped (3e19ce4, run).
- Password path never rechecks the X server after the queue; polkit does (read).
- Nothing rechecked between approval and running; `Existing` facts not compared
  (read). Install trusts `metadata().ok()`; only a real stat error reaches it.
- Cgroup failure at spawn runs the command with only a journal line; survivors of
  a failed `end()` are not reported. cgroup v1 makes `install.sh` skip its wait.
- Comment-level and doc gaps: `make` claim, `auth_admin` in the checklist,
  PLAN.md:33, "WSL works" (unsupported), `X11` means X11 under GDM, loginuid is
  best effort, "X11 sessions have no controller" is false here.
- Coding cookie after a leading bare CR (run; flagged as a finding, no Enter).
- `.pyc` content under Python-looking installs, same class as the zip check.
- strdup scrub is a dead store, confirmed by disassembly; the checklist tick was
  false. PAM_USER not read back. No core-dump limit. Missing Yama gives no note.
- Audit omits cap refusals, unregister and preview; `F-audit` was partly refuted
  (a cancel does reach the worker's final line).
- Registration pins a process, not a program: an `exec` keeps the label.
- 12 of the bypass verifier's 15 mutations survived the tests: M3, M4, M5, M6, M9,
  M14 and M1 are the ones worth pinning first.

## Also found, not verified

Reviewer reports only: neither verifier checked these, so treat each as a lead.

Medium:

- Installer picks the admin group by name and never shows it or its members;
  restricted sudoers, openSUSE's `wheel` and service accounts differ from what
  "administrator" assumes. Take `--admin-group`, or print and confirm.
- Yama: Debian and Fedora may default to `ptrace_scope` 0 (from memory), so the
  residual is worse off Ubuntu. `desktop_shell` should require positive evidence.

Medium-low or low, by area:

- Prompt: no input guard, so a requester can time when it opens; lines are not
  delimited, so content can pass for `env:` or sha lines; the agent-session
  wording kept the old claim; cwd and `--write` cut at 300.
- Dialog: invocation lines are not collapsed, so spaces can hide later arguments;
  Raw is not byte for byte; one invalid byte makes a text install "binary data";
  a dissimilar request gets no note at all; `earliest` starts before the window
  is drawn; Continue during the guard is refused.
- Daemon: connection slots held for clients that left; writing `Show` has no
  deadline and holds `prompt_lock`; cancel not rechecked after PAM; no `Running`
  state, so `wait` says `pending`; `identify` reads ancestors as root before the
  slot is taken; denial replay is keyed per process, so it misses unregistered
  agents; timeouts use `Instant`, which stops during suspend.
- Output: no truncation fields; markers are in-band; the guide does not call
  stdout untrusted.
- Execution: audit logs the request, not the resolved program, cwd and target;
  ACLs inherited when the old file had none; snapshots left on failed writes and
  no startup sweep; install temp files left after a crash; ignored directory fsync.
- Environment: `fs.suid_dumpable=1` undoes the 0711 claim; session scope matched by
  suffix; socket group and daemon group can drift; `LogRateLimitIntervalSec` needs
  systemd 240; `test-approver` has no `compile_error!` or release-build CI job;
  `install.sh` has no preflight or timeout on `wait_idle`, and never updates its
  PAM file; `pam_fprintd` messages dropped; policy text with an old polkit;
  zbus dependencies unmaintained, plan the move to 6.x.

## Refuted or narrowed

- `desktop_shell` not reading `TYPE`: not a weakness; no controller is refused and
  an Xorg controller fails the name check.
- Install over a symlink: not reachable through a request (`install_target`
  refuses it first).
- Enter on `if`/`while`/backslash forms: those go through `sh -c`, so no Enter.

## New classes

- **Tested the data, not the drawing** (1). Invariants held up to the last step.
- **Measured constant for a setting the requester controls** (2).
- **Executable identity taken as behaviour** (3).
- **A comparison by name that follows the same swap** (4).
- **Two limits on one path, set apart** (5).
- **A denylist deciding through a side door** (7): the rule was right, and the
  Enter path slipped past it. Add Enter as a checklist column.
- **Success flag standing in for "a human saw it"** (9).
- **Mutation survival**: a fix can hold today with nothing pinning it.

## Not covered

Other distros, SELinux, kernels without `SO_PEERPIDFD`, the freeze-and-kill path,
non-GNOME Wayland, and running as root on the host. `cargo-fuzz` needs nightly,
which is not installed, so a stable random-input harness stood in for it: no
coverage guidance, no sanitizers.
