# Kernel-privesc + sandbox-probing pack: design contract and known limitations

Rules: SA-PY-025..031, SA-SH-020..024 (sast.json), RD-CP-010..015
(runtime_dynamism.json). Round 3 (adversarial-review remediation).

## Severity tiering

- **critical**: exploit-shaped usage only — CLONE_NEWUSER, namespace syscalls
  with user-namespace flags / x86_64 syscall numbers / exec context /
  getattr+from-import indirection, AF_NETLINK sockets, tc mutation and
  act_pedit, capability writes (setcap/setpriv/capsh mutating), io_uring.
- **high** (SA-SH-022) / **medium** (SA-PY-031): kernel module loads
  (modprobe/insmod). Dual-use: legitimate system tooling (moby, mininet,
  nox-style test harnesses) loads modules routinely.
- **medium**: sandbox-presence probing (RD-CP-010..015), unchanged.

## False-positive guards (rounds 2-3)

- Lines whose first non-whitespace character is `#` never match SA-PY/SA-SH
  kernel rules. The comment gate is applied per PHYSICAL line: a comment line
  ending in a backslash never absorbs the next line into a suppressed logical
  line (`# \` + newline + `unshare --user sh` executes the second line in
  both bash and Python, and now fires).
- Bare library/tool PRESENCE is not an exploit signal: `import pyroute2` and
  pyroute2 references do not fire; pyroute2's fluent API `.tc('add', ...)`
  does not fire (indistinguishable per-line from the library's own tests).
  Only the pedit action shape and tc CLI / quoted-argv mutation fire.
- Namespace syscalls require exploit shaping: user-namespace flags (literal
  or numeric: CLONE_NEWUSER, 0x10000000, or decimal 268435456), a setns type
  argument, clone3, x86_64 syscall numbers (272/308/435; SA-PY-030 also
  catches 425 == io_uring_setup), an exec-context quoted token, getattr
  (incl. "un"+"share" / "set"+"ns" concat), or an ALIASED from-import.
  Definitions, docstring examples, unaliased helper imports (pyroute2's own
  shape) and CLONE_NEWNET-only calls do not fire, in decimal either
  (1073741824 == CLONE_NEWNET stays quiet).
- nsenter fires only when targeting literal PID 1 (`-t 1`, `--target=1`,
  including zero-padded spellings `-t 01`, `--target=001`), not the
  rootless-docker `-t $pid` shape.
- Read-only/diagnostic invocations excluded: `capsh --print/--decode/...`,
  `modprobe -n/-l/-L/-S/--show/--list/--dry-run/...`; `tc show` and `getcap`
  were already non-matching. Shell function definitions of modprobe/insmod
  and `echo "…modprobe…"` prose lines do not fire SA-SH-022; an echo-LED
  line still fires when a command separator (`;`, `&&`, `||`, `|`, `&`,
  backtick, `$(`/`$((`, `<(`/`>(`) precedes or wraps the module load
  (`echo "setting up"; modprobe uio`, `echo "setting up" & modprobe uio`,
  `echo $(modprobe uio)` and `echo <(modprobe uio)` are live loads wearing
  staging prose). Variable module args (`modprobe $MOD`) are not flagged
  (moby lane).
- RD-CP-013 fires only when the container-artifact probe gates behavior on
  the same line (if/&&/||/exit/return/?/unless/assert/while before the
  probe, or &&/||/exit/return/?/unless or Python or/and after it). A bare
  existence check without trailing boolean composition
  (sindresorhus/is-docker's shape) is detection tooling, not evasion; a
  combined detector that chains probes with boolean operators
  (`fs.existsSync('/.dockerenv') || fs.existsSync('/run/.containerenv')`)
  fires intentionally, because the composition is itself a gate.
- Line continuations (`unshare \` + `-Urn`) are joined in scan_sast
  preprocessing before matching; an escaped trailing backslash (`\\`) is a
  literal and not joined.

## Known limitations (documented, accepted)

- AF_NETLINK sockets whose family argument sits behind a variable or a
  paren-split expression (`fam = socket.AF_NETLINK` then `socket(fam, ...)`,
  or `socket((socket.AF_NETLINK), ...)`) do not fire SA-PY-027; only
  literal/named first arguments are matched.
- The SA-SH-022 echo-lane separator check is quote-unaware: a `;`/`|`/`&`/
  backtick/`$(`/`<(`/`>(` inside a quoted echo argument followed by modprobe
  prose
  (`echo "run: modprobe x; then reboot"`) can false-positive. Accepted:
  prose without separators stays quiet and the separator-led shape is the
  live evasion.

- unshare/setns flags behind a variable are not resolved; ctypes getattr
  chains beyond two-segment concat are not resolved.
- x86_64 syscall numbers only (272/308/435 namespace syscalls in SA-PY-026,
  425 io_uring_setup in SA-PY-030); other architectures and other syscalls
  via libc.syscall are not covered.
- Shell `$VAR`/`$(...)` command indirection is covered only in the tc lane
  (`$TC qdisc add`); general indirection, and `modprobe $MOD` specifically,
  are gaps by design (see FP guards).
- Embedded interpreters in shell (python3 -c, perl -e), PowerShell (.ps1),
  Dockerfile and CI-workflow YAML carriers are outside this regex pack.
- runtime_dynamism's regex pass does not join line continuations.
- A sandbox probe wrapped in a helper whose gating happens on another line
  is invisible to a per-line regex pack (accepted trade for not flagging
  legitimate container detectors).
