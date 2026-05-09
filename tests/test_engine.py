"""
wraith/tests/test_engine.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Engine orchestrator tests — no network required.

All HTTP calls are intercepted by a MockSession that returns
pre-canned responses, so the full engine.run() path executes
without touching any real host.

Run: python -m pytest tests/test_engine.py -v
"""

import sys
import os
import json
import tempfile
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.engine import SpecterEngine, ScanConfig, _parse_auth_headers, _build_parser
from core.logic_tester import WorkflowStep
from models.findings import ScanFinding, Severity, Category
from utils.http_client import HttpRequest, HttpResponse


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Helpers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _make_response(status: int = 200, body: str = "{}", headers: dict = None) -> HttpResponse:
    req = HttpRequest(method="GET", url="http://test.local/")
    return HttpResponse(
        status_code=status,
        headers=headers or {"content-type": "application/json"},
        body=body,
        elapsed_ms=5.0,
        request=req,
    )


class MockSession:
    """
    Replaces SpecterSession for all engine tests.
    Returns a configurable default response; individual URL overrides
    can be registered via register(path, response).
    """
    def __init__(self, default_status: int = 401, default_body: str = "{}"):
        self._default = _make_response(default_status, default_body)
        self._overrides: dict = {}
        self._base_headers: dict = {}
        self.history = []

    def register(self, path: str, response: HttpResponse):
        """Register a canned response for URLs containing `path`."""
        self._overrides[path] = response

    def send(self, req: HttpRequest) -> HttpResponse:
        for path, resp in self._overrides.items():
            if path in req.url:
                self.history.append(req)
                return resp
        self.history.append(req)
        return self._default

    # SpecterSession compatibility shims
    def set_bearer(self, token: str):
        self._base_headers["Authorization"] = f"Bearer {token}"

    def set_cookie(self, name: str, value: str):
        pass

    def clear_auth(self):
        self._base_headers.pop("Authorization", None)


def _minimal_config(**kwargs) -> ScanConfig:
    """Return a ScanConfig with all network calls disabled."""
    defaults = dict(
        target_url  = "http://test.local",
        no_report   = True,
        verbose     = False,
        phases      = ["auth", "logic", "session"],
    )
    defaults.update(kwargs)
    return ScanConfig(**defaults)


def _make_engine(config: ScanConfig, session: MockSession = None) -> SpecterEngine:
    engine = SpecterEngine(config)
    mock   = session or MockSession()
    # Patch _build_session so engine.run() uses our mock instead of opening sockets
    engine._build_session = lambda: mock
    engine._session       = mock
    return engine


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ScanConfig
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestScanConfig:
    def test_defaults_are_safe(self):
        cfg = ScanConfig(target_url="http://example.com")
        assert cfg.phases == ["auth", "logic", "session"]
        assert cfg.use_proxy is False
        assert cfg.no_report is False
        assert cfg.timeout == 15

    def test_phases_can_be_subset(self):
        cfg = ScanConfig(target_url="http://x.com", phases=["auth"])
        assert cfg.phases == ["auth"]

    def test_workflow_steps_default_empty(self):
        cfg = ScanConfig(target_url="http://x.com")
        assert cfg.workflow_steps == []

    def test_auth_headers_default_empty(self):
        cfg = ScanConfig(target_url="http://x.com")
        assert cfg.auth_headers == {}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Engine instantiation and set_workflow
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestEngineInit:
    def test_instantiates_with_config(self):
        cfg    = _minimal_config()
        engine = SpecterEngine(cfg)
        assert engine.config is cfg
        assert engine.findings == []
        assert engine._errors  == []

    def test_set_workflow_updates_config(self):
        cfg    = _minimal_config()
        engine = SpecterEngine(cfg)
        steps  = [WorkflowStep("POST", "/step1", "{}")]
        engine.set_workflow(steps)
        assert engine.config.workflow_steps == steps

    def test_version_is_semver(self):
        parts = SpecterEngine.VERSION.split(".")
        assert len(parts) == 3
        assert all(p.isdigit() for p in parts)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Phase isolation and error resilience
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPhaseIsolation:
    def test_unknown_phase_is_skipped_not_crashed(self):
        cfg = _minimal_config(phases=["auth", "nonexistent", "session"])
        engine = _make_engine(cfg)
        # Should complete without raising
        findings = engine.run()
        assert isinstance(findings, list)

    def test_phase_exception_does_not_abort_subsequent_phases(self):
        """If one phase raises, the others must still run."""
        cfg    = _minimal_config(phases=["auth", "logic", "session"])
        engine = _make_engine(cfg)

        call_log = []

        def boom():
            call_log.append("auth")
            raise RuntimeError("simulated auth phase crash")

        def ok_logic():
            call_log.append("logic")
            return []

        def ok_session():
            call_log.append("session")
            return []

        engine._run_auth_phase    = boom
        engine._run_logic_phase   = ok_logic
        engine._run_session_phase = ok_session

        findings = engine.run()
        assert "auth"    in call_log
        assert "logic"   in call_log
        assert "session" in call_log
        assert len(engine._errors) == 1
        assert "simulated auth phase crash" in engine._errors[0]

    def test_findings_from_all_phases_are_merged(self):
        cfg    = _minimal_config(phases=["auth", "logic", "session"])
        engine = _make_engine(cfg)

        def _finding(title: str) -> ScanFinding:
            return ScanFinding(title=title, severity=Severity.HIGH,
                               category=Category.AUTH, phase="auth")

        engine._run_auth_phase    = lambda: [_finding("A1"), _finding("A2")]
        engine._run_logic_phase   = lambda: [_finding("L1")]
        engine._run_session_phase = lambda: [_finding("S1")]

        findings = engine.run()
        titles = [f.title for f in findings]
        assert "A1" in titles
        assert "A2" in titles
        assert "L1" in titles
        assert "S1" in titles
        assert len(findings) == 4

    def test_single_phase_run(self):
        cfg    = _minimal_config(phases=["auth"])
        engine = _make_engine(cfg)
        engine._run_auth_phase = lambda: []
        findings = engine.run()
        assert isinstance(findings, list)

    def test_empty_phases_list_returns_empty(self):
        cfg    = _minimal_config(phases=[])
        engine = _make_engine(cfg)
        findings = engine.run()
        assert findings == []


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Report writing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestReportWriting:
    def test_no_report_flag_skips_file_creation(self, tmp_path):
        cfg    = _minimal_config(no_report=True, output_dir=str(tmp_path))
        engine = _make_engine(cfg)
        engine._run_auth_phase    = lambda: []
        engine._run_logic_phase   = lambda: []
        engine._run_session_phase = lambda: []
        engine.run()
        assert list(tmp_path.iterdir()) == []

    def test_report_files_created_when_flag_off(self, tmp_path):
        cfg    = _minimal_config(no_report=False, output_dir=str(tmp_path))
        engine = _make_engine(cfg)
        engine._run_auth_phase    = lambda: []
        engine._run_logic_phase   = lambda: []
        engine._run_session_phase = lambda: []
        engine.run()
        files = [f.name for f in tmp_path.iterdir()]
        assert any(f.endswith(".json") for f in files)
        assert any(f.endswith(".html") for f in files)

    def test_json_report_valid_structure(self, tmp_path):
        finding = ScanFinding(
            title    = "Test Finding",
            severity = Severity.CRITICAL,
            category = Category.AUTH,
            phase    = "auth",
        )
        cfg    = _minimal_config(no_report=False, output_dir=str(tmp_path))
        engine = _make_engine(cfg)
        engine._run_auth_phase    = lambda: [finding]
        engine._run_logic_phase   = lambda: []
        engine._run_session_phase = lambda: []
        engine.run()

        json_files = [f for f in tmp_path.iterdir() if f.suffix == ".json"]
        assert len(json_files) == 1
        data = json.loads(json_files[0].read_text())
        assert "meta"     in data
        assert "summary"  in data
        assert "findings" in data
        assert data["meta"]["total_findings"] == 1
        assert data["findings"][0]["title"] == "Test Finding"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI — argument parsing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCLIParser:
    def test_target_required(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args([])

    def test_target_parsed(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://target.com"])
        assert args.target == "https://target.com"

    def test_phases_default_all(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://x.com"])
        assert set(args.phases) == {"auth", "logic", "session"}

    def test_phases_subset(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://x.com", "--phases", "auth", "session"])
        assert args.phases == ["auth", "session"]

    def test_proxy_flag_defaults_false(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://x.com"])
        assert args.proxy is False

    def test_proxy_flag_set(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://x.com", "--proxy"])
        assert args.proxy is True

    def test_no_report_flag(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://x.com", "--no-report"])
        assert args.no_report is True

    def test_auth_header_repeatable(self):
        parser = _build_parser()
        args   = parser.parse_args([
            "--target", "https://x.com",
            "--auth-header", "Authorization: Bearer tok",
            "--auth-header", "X-Tenant: acme",
        ])
        assert len(args.auth_headers) == 2

    def test_timeout_parsed_as_int(self):
        parser = _build_parser()
        args   = parser.parse_args(["--target", "https://x.com", "--timeout", "30"])
        assert args.timeout == 30

    def test_invalid_phase_rejected(self):
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--target", "https://x.com", "--phases", "fakePhase"])


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# _parse_auth_headers
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestParseAuthHeaders:
    def test_single_header(self):
        result = _parse_auth_headers(["Authorization: Bearer tok123"])
        assert result == {"Authorization": "Bearer tok123"}

    def test_multiple_headers(self):
        result = _parse_auth_headers([
            "Authorization: Bearer tok",
            "X-Tenant: acme",
        ])
        assert result["Authorization"] == "Bearer tok"
        assert result["X-Tenant"]      == "acme"

    def test_empty_list(self):
        assert _parse_auth_headers([]) == {}

    def test_malformed_entry_skipped(self):
        result = _parse_auth_headers(["no-colon-here", "Good: header"])
        assert "no-colon-here" not in result
        assert result["Good"] == "header"

    def test_value_with_colon_preserved(self):
        # e.g. "Authorization: Bearer a:b:c" — only first colon is the separator
        result = _parse_auth_headers(["Authorization: Bearer a:b:c"])
        assert result["Authorization"] == "Bearer a:b:c"

    def test_whitespace_stripped(self):
        result = _parse_auth_headers(["  X-Key  :  value  "])
        assert result["X-Key"] == "value"