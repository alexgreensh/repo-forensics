"""Hardening for the ST-PR-010 workflow-expression downgrade (scan_skill_threats)."""

import os
import sys
import time

import pytest

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
sys.path.insert(0, SCRIPTS)

import scan_skill_threats  # noqa: E402

HEAD = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
WF = ".github/workflows/a.yml"


def _pr010(content):
    return [(f.line, f.severity)
            for f in scan_skill_threats.scan_content(content, WF) if f.rule_id == "ST-PR-010"]


def _severities(content):
    return {sev for _line, sev in _pr010(content)}


class TestMultiLineScalarsCannotMaskAnExpression:
    """A key-shaped line inside a quoted scalar or flow collection is text, not a
    field. github.ref_name is attacker-chosen (a branch can be named $(...))."""

    @pytest.mark.parametrize("step", [
        '      - run: "echo\n        name: ${{ github.ref_name }}"\n',
        "      - run: 'echo\n        name: ${{ github.ref_name }}'\n",
        '      - run: ["echo\n        name: ${{ github.ref_name }}"]\n',
        '      - "echo\n        name: ${{ github.ref_name }}"\n',
        '      - run: !!str "echo\n        name: ${{ github.ref_name }}"\n',
        '      - run: !!str  "echo\n        name: ${{ github.ref_name }}"\n',
        '      - - "echo\n        name: ${{ github.ref_name }}"\n',
        '      - run: [\n        name: ${{ github.ref_name }}]\n',
        '      - run: "a\\"\n        name: ${{ github.ref_name }}"\n',
        "      - run: 'a''\n        name: ${{ github.ref_name }}'\n",
    ])
    def test_expression_stays_high(self, step):
        found = _pr010(HEAD + step)
        assert found and {sev for _line, sev in found} == {"high"}

    def test_real_name_field_is_still_low(self):
        assert _pr010(HEAD + "      - name: ${{ github.ref_name }}\n        run: echo hi\n") == [(6, "low")]

    def test_closed_quote_and_apostrophe_do_not_block_the_downgrade(self):
        assert _severities(HEAD + '      - name: "a ${{ github.ref_name }}"\n        run: echo hi\n') == {"low"}
        assert _severities(HEAD + "      - name: it's ${{ github.ref_name }}\n        run: echo hi\n") == {"low"}
        assert _severities(HEAD + "      - name: 'it''s ${{ github.ref_name }}'\n        run: echo hi\n") == {"low"}


class TestLineBreaksKeepFindingLinesAligned:
    @pytest.mark.parametrize("sep", ["\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029"])
    def test_stray_break_cannot_shift_a_downgrade_onto_the_wrong_line(self, sep):
        wf = ("x: 1" + sep + "\non: issues\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
              "      - name: ${{ github.sha }}\n        run: echo ${{ github.head_ref }}\n")
        found = dict(_pr010(wf))
        assert found[8] == "high"
        assert set(found.values()) == {"high"}

    def test_lone_carriage_return_blocks_downgrades(self):
        wf = HEAD + "      - name: ${{ github.sha }}\r        run: echo ${{ github.head_ref }}\n"
        assert _severities(wf) == {"high"}

    def test_crlf_files_are_still_graded(self):
        wf = (HEAD + "      - name: ${{ github.ref_name }}\n        run: echo ${{ github.head_ref }}\n"
              ).replace("\n", "\r\n")
        assert _pr010(wf) == [(6, "low"), (7, "high")]


class TestBoundedWork:
    BASE = HEAD + "      - name: x\n        with:\n          k: "

    def _timed(self, content):
        start = time.perf_counter()
        found = _pr010(content)
        return found, time.perf_counter() - start

    def test_unclosed_expressions_scan_in_linear_time(self):
        _found, elapsed = self._timed(self.BASE + "${{ a " * 40000 + "\n")
        assert elapsed < 3.0

    def test_many_closed_expressions_on_one_line_scan_in_linear_time(self):
        _found, elapsed = self._timed("name: " + "${{ github.ref }}" * 4000 + "\n")
        assert elapsed < 3.0

    def test_bracket_heavy_lines_are_bounded(self):
        line = "      - name: " + "${{ steps[" * 380
        _found, elapsed = self._timed(HEAD + "\n".join([line[:4000]] * 100) + "\n")
        assert elapsed < 5.0

    def test_overlong_line_is_never_downgraded(self):
        found = _pr010("name: ${{ github.ref }}" + " " * 5000 + "\non: push\n")
        assert found and {sev for _line, sev in found} == {"high"}

    def test_downgrade_budget_fails_closed(self):
        line = "      - name: ${{ github.sha }} " + "x" * 3000 + "\n"
        found = _pr010(HEAD + line * 40)
        assert any(sev == "high" for _line, sev in found)
        assert any(sev == "low" for _line, sev in found)


class TestUntrustedLineCheck:
    @pytest.mark.parametrize("line,expected", [
        ("name: ${{ github.event.issue.title }}", True),
        ("name: ${{ github.sha }} ${{ github.head_ref }}", True),
        ("name: ${{ github.sha }} inputs", True),          # outside the braces still counts
        ("name: inputs ${{ github.sha }}", False),         # before the first ${{ does not
        ("name: ${{ steps.a.outputs.b }}", True),
        ("name: ${{ needs [ 'a' ] . outputs }}", True),
        ("name: ${{ needs[a].outputs.x }}", True),
        ("name: ${{ env.X }}", True),
        ("name: ${{ github.ref_name }}", False),
        ("name: plain", False),
    ])
    def test_cases(self, line, expected):
        assert scan_skill_threats._workflow_untrusted(line) is expected


class TestStructuralTricksCannotMaskAnExpression:
    """Review round 1: shapes where the executable value is not where a plain
    `key: value` reading puts it. Each must leave the expression high."""

    HEAD2 = "name: test\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"

    @pytest.mark.parametrize("step", [
        "      - ? run\n        : |\n          name: ${{ github.ref_name }}\n",
        "      - ?\n          run\n        :\n          name: ${{ github.ref_name }}\n",
        "      - run: !!str |\n          name: ${{ github.ref_name }}\n",
        "      - run: !!str >2-\n          name: ${{ github.ref_name }}\n",
        "      - run: !<tag:yaml.org,2002:str> |\n          name: ${{ github.ref_name }}\n",
        "      - run: &a |\n          name: ${{ github.ref_name }}\n",
        "      -    name: |\n             harmless\n           run: echo ${{ github.ref_name }}\n",
        "      -\tname: x\n        run: echo ${{ github.ref_name }}\n",
        "      - |\n        name: ${{ github.ref_name }}\n",
    ])
    def test_stays_high(self, step):
        found = _pr010(self.HEAD2 + step)
        assert found and {sev for _line, sev in found} == {"high"}

    @pytest.mark.parametrize("step", [
        "      - run: |\n          name: ${{ github.ref_name }}\n",
        "      - run: |4-\n            name: ${{ github.ref_name }}\n",
    ])
    def test_plain_block_scalar_controls_stay_high(self, step):
        assert {sev for _line, sev in _pr010(self.HEAD2 + step)} == {"high"}

    def test_wide_dash_spacing_still_grades_a_real_name(self):
        wf = self.HEAD2 + "      -   name: ${{ github.ref_name }}\n          run: echo hi\n"
        assert _pr010(wf) == [(7, "low")]


class TestScanFileKeepsLoneCarriageReturns:
    @pytest.mark.parametrize("raw", [
        b"name: ${{ github.ref }}\ron: push\r",
        b"name: ${{ github.ref }}\r\non: push\rjobs:\r\n",
    ])
    def test_disk_read_matches_memory_read(self, tmp_path, raw):
        path = tmp_path / "wf.yml"
        path.write_bytes(raw)
        disk = [f.severity for f in scan_skill_threats.scan_file(str(path), WF)
                if f.rule_id == "ST-PR-010"]
        assert disk and set(disk) == {"high"}

    def test_plain_crlf_file_on_disk_is_still_graded(self, tmp_path):
        path = tmp_path / "wf.yml"
        path.write_bytes((HEAD + "      - name: ${{ github.ref_name }}\n        run: echo hi\n")
                         .replace("\n", "\r\n").encode())
        disk = [f.severity for f in scan_skill_threats.scan_file(str(path), WF)
                if f.rule_id == "ST-PR-010"]
        assert disk == ["low"]


class TestTagOnlyValues:
    @pytest.mark.parametrize("step", [
        "      - run: !\n          name: ${{ github.ref_name }}\n",
        "      - run: !t |\n          name: ${{ github.ref_name }}\n",
        "      - run: ! >-\n          name: ${{ github.ref_name }}\n",
        "      - run: !!str\n          |\n          name: ${{ github.ref_name }}\n",
    ])
    def test_stays_high(self, step):
        found = _pr010("name: t\non: push\njobs:\n  b:\n    runs-on: x\n    steps:\n" + step)
        assert found and {sev for _line, sev in found} == {"high"}


class TestSeparatorsAndBrackets:
    HEAD3 = "on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"

    @pytest.mark.parametrize("sep", ["\u00a0", "\u2003", "\u3000"])
    def test_unicode_space_after_colon_is_not_a_separator(self, sep):
        wf = self.HEAD3 + "      - run: echo\n          name:" + sep + "${{ github.ref_name }}\n"
        found = _pr010(wf)
        assert found and {sev for _line, sev in found} == {"high"}

    def test_unicode_space_indent_is_not_indentation(self):
        wf = self.HEAD3 + "      - run: echo\n\u00a0         name: ${{ github.ref_name }}\n"
        assert {sev for _line, sev in _pr010(wf)} == {"high"}

    @pytest.mark.parametrize("step", [
        "      - name: ${{ github.sha }}\n        run: grep -F '[' README.md\n",
        "      - name: ${{ github.sha }}\n        run: test -f /tmp/a-[\n",
        "      - name: ${{ github.sha }}\n        run: echo a:[\n",
        "      - name: Building [${{ github.sha }}\n        run: echo ok\n",
    ])
    def test_mid_scalar_bracket_does_not_open_a_flow_collection(self, step):
        found = _pr010(self.HEAD3 + step)
        assert [sev for _l, sev in found] == ["low"]

    def test_value_start_bracket_still_opens_flow(self):
        wf = self.HEAD3 + "      - run: [\n        name: ${{ github.ref_name }}]\n"
        assert {sev for _line, sev in _pr010(wf)} == {"high"}


class TestTextAfterLeadingExpression:
    @pytest.mark.parametrize("name", [
        "${{ github.ref_name }}'s CI", "${{ github.ref_name }} [CI", '${{ github.ref_name }} "CI',
    ])
    def test_quote_or_bracket_after_an_expression_is_text(self, name):
        wf = TestSeparatorsAndBrackets.HEAD3 + "      - name: " + name + "\n        run: echo ok\n"
        assert [sev for _l, sev in _pr010(wf)] == ["low"]


class TestSequenceAtKeyIndent:
    def test_compact_sequence_under_its_key_stays_graded_high(self):
        wf = ("on: push\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n"
              "    - name: ${{ github.sha }}\n      run: echo ok\n"
              "    - run: echo ${{ github.ref_name }}\n")
        assert [sev for _l, sev in _pr010(wf)] == ["high", "high"]

    def test_item_at_a_job_key_indent_is_not_graded_inert(self):
        wf = ("on: push\njobs:\n  b:\n  - environment: ${{ matrix.x }}\n"
              "    runs-on: ubuntu-latest\n")
        assert all(sev == "high" for _l, sev in _pr010(wf))
