import json
import hashlib
import importlib.util
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import refresh_controller as controller


def _redirect_state(monkeypatch, tmp_path):
    home = tmp_path / "home with spaces"
    cache = home / ".cache" / "repo-forensics"
    data = home / ".local" / "share" / "repo-forensics"
    values = {
        "HOME": home,
        "CACHE_DIR": cache,
        "DATA_DIR": data,
        "VERSIONS_DIR": data / "versions",
        "ACTIVE_STATE": data / "active.json",
        "REFRESH_STATE": cache / "refresh-state.json",
        "SUCCESS_MARKER": cache / ".last-refresh",
        "ATTEMPT_MARKER": cache / ".last-refresh-attempt",
        "DISABLED_MARKER": cache / "refresh.disabled",
        "CONTROLLER_LOCK": cache / "controller.lock",
        "BOOTSTRAP_LOG": cache / "scheduler.log",
        "REFRESH_STDIO_LOG": cache / "refresh-stdio.log",
    }
    for name, value in values.items():
        monkeypatch.setattr(controller, name, value)
    return home, cache, data


def _signed_candidate(monkeypatch, tmp_path):
    skill = tmp_path / "signed-skill"
    for rel in controller.REQUIRED_PAYLOAD_FILES:
        path = skill / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"# {rel}\n")
    files = {
        rel: hashlib.sha256((skill / rel).read_bytes()).hexdigest()
        for rel in sorted(controller.REQUIRED_PAYLOAD_FILES)
    }
    manifest = json.dumps({
        "version": "2", "file_count": len(files), "files": files,
    }, indent=2).encode() + b"\n"
    (skill / "checksums.json").write_bytes(manifest)
    signer_path = Path(__file__).resolve().parents[3] / "scripts" / "_ed25519_sign.py"
    spec = importlib.util.spec_from_file_location("test_release_signer", signer_path)
    signer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(signer)
    seed = bytes(range(32))
    _private, public = signer.keypair(seed)
    (skill / "checksums.json.sig").write_bytes(signer.sign(manifest, seed, public))
    monkeypatch.setattr(controller, "CHECKSUMS_PUBKEY_HEX", public.hex())
    return skill


def test_future_attempt_and_success_markers_are_due(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    controller.SUCCESS_MARKER.parent.mkdir(parents=True)
    controller.SUCCESS_MARKER.write_text("future")
    future = time.time() + 86400
    os.utime(controller.SUCCESS_MARKER, (future, future))

    assert controller._timestamp_is_due(controller.SUCCESS_MARKER, 86400)


def test_signed_complete_manifest_rejects_tamper_and_unexpected_files(monkeypatch, tmp_path):
    skill = _signed_candidate(monkeypatch, tmp_path)
    assert controller._verify_skill(skill) == (True, "verified")

    extra = skill / "scripts" / "unmanifested.py"
    extra.write_text("print('unexpected')\n")
    ok, detail = controller._verify_skill(skill)
    assert ok is False and "unexpected files" in detail
    extra.unlink()

    target = skill / "scripts" / "ioc_manager.py"
    target.write_text("# tampered\n")
    ok, detail = controller._verify_skill(skill)
    assert ok is False and "integrity mismatch" in detail


def test_signed_manifest_rejects_wrong_signature(monkeypatch, tmp_path):
    skill = _signed_candidate(monkeypatch, tmp_path)
    (skill / "checksums.json.sig").write_bytes(b"x" * 64)

    ok, detail = controller._verify_skill(skill)

    assert ok is False
    assert "signature invalid" in detail


def test_verify_ignores_payload_supplied_verifier(monkeypatch, tmp_path):
    # Trust-model regression: the candidate payload is required to carry its own
    # scripts/_ed25519.py. A hostile payload could ship a permissive verifier
    # that approves any signature. _verify_skill must use the controller's own
    # trusted verifier and never the candidate's, so a bad signature is still
    # rejected even when the payload's verifier would have accepted it.
    skill = _signed_candidate(monkeypatch, tmp_path)
    (skill / "checksums.json.sig").write_bytes(b"x" * 64)
    (skill / "scripts" / "_ed25519.py").write_text(
        "def verify(signature, message, public_key):\n    return True\n"
    )

    ok, detail = controller._verify_skill(skill)

    assert ok is False
    assert "signature invalid" in detail
    # The trusted verifier (this repo's own _ed25519) must own the cache slot.
    assert sys.modules["_ed25519"].__file__ == str(
        controller._TRUSTED_SCRIPTS_DIR / "_ed25519.py"
    )


def test_promotion_never_downgrades_active_cross_agent_payload(monkeypatch, tmp_path):
    _home, _cache, data = _redirect_state(monkeypatch, tmp_path)
    active_skill = data / "versions" / "3.0.0"
    scripts = active_skill / "scripts"
    scripts.mkdir(parents=True)
    (active_skill / "VERSION").write_text("3.0.0\n")
    refresh = scripts / "refresh_threat_dbs.py"
    refresh.write_text("# active\n")
    (scripts / "refresh_controller.py").write_text("# active controller\n")
    active = {"version": "3.0.0", "refresh_script": str(refresh),
              "controller": str(scripts / "refresh_controller.py")}
    controller.ACTIVE_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.ACTIVE_STATE.write_text(json.dumps(active))
    candidate = tmp_path / "older" / "skills" / "repo-forensics"
    candidate.mkdir(parents=True)
    (candidate / "checksums.json").write_text("{}\n")
    monkeypatch.setattr(controller, "_candidate", lambda: (candidate, "2.11.5"))
    monkeypatch.setattr(controller, "_verify_skill", lambda _path: (True, "verified"))

    selected = controller.promote_payload()

    assert selected["version"] == "3.0.0"
    assert not (controller.VERSIONS_DIR / "2.11.5").exists()


def test_promotion_copies_verified_payload_to_stable_version(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    candidate = tmp_path / "plugin" / "skills" / "repo-forensics"
    scripts = candidate / "scripts"
    scripts.mkdir(parents=True)
    (scripts / "refresh_threat_dbs.py").write_text("# refresh\n")
    (scripts / "refresh_controller.py").write_text("# controller\n")
    (candidate / "checksums.json").write_text("{}\n")
    monkeypatch.setattr(controller, "_candidate", lambda: (candidate, "2.11.5"))
    monkeypatch.setattr(controller, "_verify_skill", lambda _path: (True, "verified"))
    monkeypatch.setattr(controller.subprocess, "run", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout="", stderr=""))

    active = controller.promote_payload()

    assert active["version"] == "2.11.5"
    assert Path(active["refresh_script"]).is_file()
    assert Path(active["controller"]).is_file()
    assert Path(active["refresh_script"]).parents[1].joinpath("VERSION").read_text().strip() == "2.11.5"


def test_scheduler_targets_stable_controller_not_refresh_script(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    active = {"controller": "/stable/controller.py", "refresh_script": "/stable/refresh.py"}

    plist = controller._mac_plist(active)
    service = controller._systemd_quote("/stable/controller.py")
    windows = controller._windows_task_command(active)

    assert plist["ProgramArguments"][-2:] == ["/stable/controller.py", "run"]
    assert service in f"ExecStart={service} run"
    assert "/stable/controller.py" in windows and windows.endswith(" run")
    assert controller.LABEL.endswith("-v2")
    assert controller.LABEL != controller.LEGACY_LABEL


def test_status_is_machine_readable_per_feed(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    skill = controller.VERSIONS_DIR / "2.11.5"
    scripts = skill / "scripts"
    scripts.mkdir(parents=True)
    (skill / "VERSION").write_text("2.11.5\n")
    refresh = scripts / "refresh_threat_dbs.py"
    refresh.write_text("# refresh\n")
    controller.ACTIVE_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.ACTIVE_STATE.write_text(json.dumps({
        "version": "2.11.5", "refresh_script": str(refresh),
        "controller": str(scripts / "refresh_controller.py")}))
    controller.REFRESH_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.REFRESH_STATE.write_text(json.dumps({
        "status": "degraded", "last_attempt": 10,
        "feeds": {"ioc": {"ok": True}, "kev": {"ok": False}}}))

    result = controller.status()

    assert result["status"] == "degraded"
    assert result["feeds"]["kev"]["ok"] is False
    assert result["active_version"] == "2.11.5"


def test_existing_stable_controller_authenticates_future_candidate(monkeypatch, tmp_path):
    _home, _cache, data = _redirect_state(monkeypatch, tmp_path)
    stable = data / "versions" / "2.11.4" / "scripts" / "refresh_controller.py"
    stable.parent.mkdir(parents=True)
    stable.write_text("# stable\n")
    candidate = tmp_path / "marketplace" / "skills" / "repo-forensics"
    candidate.mkdir(parents=True)
    controller.ACTIVE_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.ACTIVE_STATE.write_text(json.dumps({
        "version": "2.11.4", "controller": str(stable),
        "refresh_script": str(stable.with_name("refresh_threat_dbs.py")),
    }))
    monkeypatch.setattr(controller, "_active_is_usable", lambda _active: True)
    seen = {}

    def fake_run(args, **_kwargs):
        seen["args"] = args
        return SimpleNamespace(returncode=0, stdout='{"ok": true, "status": "ready"}\n', stderr="")

    monkeypatch.setattr(controller.subprocess, "run", fake_run)
    result = controller._delegate_to_stable(candidate)

    assert result["ok"] is True
    assert result["delegated_to_stable"] is True
    assert seen["args"][1:] == [str(stable.resolve()), "adopt", "--candidate",
                                str(candidate), "--json"]


def test_stable_controller_delegation_failure_is_fail_closed(monkeypatch, tmp_path):
    _home, _cache, data = _redirect_state(monkeypatch, tmp_path)
    stable = data / "versions" / "2.11.4" / "scripts" / "refresh_controller.py"
    stable.parent.mkdir(parents=True)
    stable.write_text("# stable\n")
    controller.ACTIVE_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.ACTIVE_STATE.write_text(json.dumps({
        "version": "2.11.4", "controller": str(stable), "refresh_script": str(stable),
    }))
    monkeypatch.setattr(controller, "_active_is_usable", lambda _active: True)
    monkeypatch.setattr(controller.subprocess, "run", lambda *_a, **_k: SimpleNamespace(
        returncode=1, stdout="not-json\n", stderr="boom"))

    result = controller._delegate_to_stable(tmp_path / "candidate")

    assert result["ok"] is False
    assert result["delegated_to_stable"] is True
    assert "delegation failed" in result["error"]


def test_failed_candidate_self_check_preserves_active_pointer(monkeypatch, tmp_path):
    _home, _cache, data = _redirect_state(monkeypatch, tmp_path)
    old = {"version": "2.11.4", "controller": "/old/controller.py",
           "refresh_script": "/old/refresh.py"}
    controller.ACTIVE_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.ACTIVE_STATE.write_text(json.dumps(old))
    candidate = tmp_path / "candidate"
    (candidate / "scripts").mkdir(parents=True)
    (candidate / "scripts" / "refresh_controller.py").write_text("# controller\n")
    (candidate / "scripts" / "refresh_threat_dbs.py").write_text("# refresh\n")
    (candidate / "checksums.json").write_text("{}\n")
    monkeypatch.setattr(controller, "_candidate", lambda *_a: (candidate, "2.11.5"))
    monkeypatch.setattr(controller, "_verify_skill", lambda _path: (True, "verified"))
    monkeypatch.setattr(controller, "_active_is_usable", lambda _active: False)
    monkeypatch.setattr(controller.subprocess, "run", lambda *_a, **_k: SimpleNamespace(
        returncode=1, stdout="", stderr="self-check failed"))

    try:
        controller.promote_payload(candidate)
    except RuntimeError as exc:
        assert "self-check failed" in str(exc)
    else:
        raise AssertionError("promotion unexpectedly succeeded")

    assert json.loads(controller.ACTIVE_STATE.read_text()) == old


def test_attempt_throttle_has_one_atomic_source(monkeypatch, tmp_path):
    _home, cache, _data = _redirect_state(monkeypatch, tmp_path)
    controller._mark_attempt()

    state = json.loads(controller.REFRESH_STATE.read_text())
    assert isinstance(state["last_attempt"], float)
    assert state["trigger_status"] == "requested"
    assert not controller.ATTEMPT_MARKER.exists()
    assert controller._attempt_due() is False


def test_status_rejects_future_success_marker(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    controller.SUCCESS_MARKER.parent.mkdir(parents=True)
    controller.SUCCESS_MARKER.write_text("future")
    future = time.time() + 3600
    os.utime(controller.SUCCESS_MARKER, (future, future))
    controller.REFRESH_STATE.write_text(json.dumps({
        "status": "healthy", "feeds": {"ioc": {"ok": True}},
    }))
    monkeypatch.setattr(controller, "_active_is_usable", lambda _active: True)
    monkeypatch.setattr(controller, "_scheduler_status", lambda _active: (True, "healthy"))

    result = controller.status()

    assert result["ok"] is False
    assert result["clock_skew"] is True
    assert result["refresh_healthy"] is False


def test_run_reports_worker_degradation_despite_zero_exit(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    controller.ACTIVE_STATE.parent.mkdir(parents=True, exist_ok=True)
    controller.ACTIVE_STATE.write_text(json.dumps({
        "version": "2.11.5", "controller": "/stable/controller.py",
        "refresh_script": "/stable/refresh.py",
    }))
    monkeypatch.setattr(controller, "_active_is_usable", lambda _active: True)

    def fake_run(_args, **kwargs):
        run_id = kwargs["env"]["REPO_FORENSICS_RUN_ID"]
        controller.REFRESH_STATE.write_text(json.dumps({
            "run_id": run_id, "status": "degraded",
            "feeds": {"ioc": {"ok": False}},
        }))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(controller.subprocess, "run", fake_run)
    result = controller.run_active()

    assert result["operation_ok"] is True
    assert result["ok"] is False
    assert result["refresh_healthy"] is False
    assert result["status"] == "degraded"


def test_disable_exit_code_tracks_scheduler_removal_not_health(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    monkeypatch.setattr(controller, "_remove_all_schedulers", lambda: (True, "removed"))

    assert controller.main(["disable", "--json"]) == 0
    assert controller.DISABLED_MARKER.is_file()


def test_enable_when_never_disabled_does_not_crash(monkeypatch, tmp_path):
    # Regression: `enable` with no pre-existing disable marker used to leave
    # `result` unbound (FileNotFoundError silenced, else-branch skipped) and
    # crash with NameError — the exact command the boot warning tells users to
    # run to re-enable refresh.
    _redirect_state(monkeypatch, tmp_path)
    monkeypatch.setattr(controller, "ensure",
                        lambda *a, **k: {"ok": True, "operation_ok": True, "status": "ready"})
    assert not controller.DISABLED_MARKER.exists()

    assert controller.main(["enable", "--json"]) == 0


def test_enable_removes_existing_marker(monkeypatch, tmp_path):
    _redirect_state(monkeypatch, tmp_path)
    controller.DISABLED_MARKER.parent.mkdir(parents=True, exist_ok=True)
    controller.DISABLED_MARKER.write_text("disabled by user\n")
    monkeypatch.setattr(controller, "ensure",
                        lambda *a, **k: {"ok": True, "operation_ok": True, "status": "ready"})

    assert controller.main(["enable", "--json"]) == 0
    assert not controller.DISABLED_MARKER.exists()


def test_version_tuple_handles_non_string():
    # Regression: a JSON-null version field reached _version_tuple as None and
    # raised AttributeError (not caught by the TypeError/ValueError guard).
    assert controller._version_tuple(None) == ()
    assert controller._version_tuple(123) == ()
    assert controller._version_tuple("") == ()
    assert controller._version_tuple("2.11.5") == (2, 11, 5)


def test_controller_lock_excludes_same_process_reentry(monkeypatch, tmp_path):
    # POSIX flock is per-process, so two threads could both pass the file lock.
    # The in-process mutex must reject a second concurrent acquisition.
    _redirect_state(monkeypatch, tmp_path)
    controller.CACHE_DIR.mkdir(parents=True, exist_ok=True)
    with controller._ControllerLock():
        try:
            with controller._ControllerLock():
                raised = False
        except BlockingIOError:
            raised = True
    assert raised, "second same-process lock acquisition should raise BlockingIOError"
    # Lock is fully released afterwards: a fresh acquisition now succeeds.
    with controller._ControllerLock():
        pass
