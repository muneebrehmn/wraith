"""
wraith/tests/test_phase2.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 2 tests — AuthTester

Uses a MockSession (no real network) that returns pre-scripted responses.
Run: python -m pytest tests/test_phase2.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import base64
import hmac
import hashlib
from typing import Dict, Optional
from unittest.mock import MagicMock

from utils.http_client import HttpRequest, HttpResponse, WraithSession
from core.auth_tester import AuthTester, AuthTarget
from models.findings import Severity


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Test infrastructure — mock session + JWT factory
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _b64e(d: dict) -> str:
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(",", ":")).encode()
    ).rstrip(b"=").decode()


def make_jwt(header: dict, payload: dict, secret: str = "", alg: str = "HS256") -> str:
    """Build a real signed JWT for testing."""
    h = _b64e(header)
    p = _b64e(payload)
    if alg.upper() == "NONE" or not secret:
        return f"{h}.{p}."
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384}[alg.upper()]
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), fn).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


def mock_response(
    status: int = 200,
    body: str   = "{}",
    headers: Optional[Dict] = None,
    req: Optional[HttpRequest] = None,
) -> HttpResponse:
    """Helper: build a fake HttpResponse for injection into the mock session."""
    return HttpResponse(
        status_code = status,
        headers     = headers or {"content-type": "application/json"},
        body        = body,
        elapsed_ms  = 10.0,
        request     = req or HttpRequest(method="GET", url="http://test/"),
    )


class MockSession:
    """
    Replaces WraithSession during tests.
    Scripts responses via a dict keyed on (method, url_fragment).
    Falls back to a default 200 response.
    """

    def __init__(self, routes: Dict[str, HttpResponse]):
        # routes: {"/endpoint": HttpResponse, ...}
        self.routes  = routes
        self.history = []

    def send(self, req: HttpRequest) -> HttpResponse:
        # Match the longest route key found in the URL
        for path, resp in self.routes.items():
            if path in req.url:
                resp.request = req
                self.history.append(resp)
                return resp
        # Default: 200 empty
        default = mock_response(200, "{}", req=req)
        self.history.append(default)
        return default


def _make_target(**kwargs) -> AuthTarget:
    """Base target with sane defaults for tests."""
    return AuthTarget(
        base_url            = "http://target.test",
        login_endpoint      = "/login",
        login_body          = json.dumps({"username": "admin", "password": "admin"}),
        login_token_field   = "token",
        protected_endpoint  = "/api/me",
        **kwargs,
    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JWT None-Alg tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestNoneAlg:
    def _setup(self, protected_status=200, protected_body='{"user":"admin"}'):
        """Shared setup: login returns a valid JWT; protected endpoint accepts anything."""
        valid_jwt = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, "secret")
        session = MockSession({
            "/login":  mock_response(200, json.dumps({"token": valid_jwt})),
            "/api/me": mock_response(protected_status, protected_body),
        })
        target  = _make_target()
        tester  = AuthTester(session, target)
        return tester, valid_jwt

    def test_none_alg_bypass_detected(self):
        """Vulnerable app: /api/me returns 200 for forged none-alg token → CRITICAL finding."""
        tester, _ = self._setup(protected_status=200, protected_body='{"user":"admin"}')
        tester.run_all()
        titles = [f.title for f in tester.findings]
        assert any("None-Algorithm" in t for t in titles)
        critical = [f for f in tester.findings if f.severity == Severity.CRITICAL]
        assert any("None-Algorithm" in f.title for f in critical)

    def test_none_alg_not_flagged_when_rejected(self):
        """Secure app: /api/me returns 401 for forged token → no none-alg finding."""
        tester, _ = self._setup(protected_status=401, protected_body='{"error":"unauthorized"}')
        tester.run_all()
        assert not any("None-Algorithm" in f.title for f in tester.findings)

    def test_no_token_no_crash(self):
        """Login fails → AuthTester should not crash, just skip JWT checks."""
        session = MockSession({"/login": mock_response(401, '{"error":"bad creds"}')})
        tester  = AuthTester(session, _make_target())
        findings = tester.run_all()   # should not raise
        assert isinstance(findings, list)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Token extraction tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTokenExtraction:
    def _tester(self):
        return AuthTester(MockSession({}), _make_target())

    def test_extracts_top_level_json_field(self):
        t = self._tester()
        resp = mock_response(200, '{"token": "abc123"}')
        assert t._extract_token(resp, "token") == "abc123"

    def test_extracts_nested_json_field(self):
        t = self._tester()
        resp = mock_response(200, '{"data": {"auth": {"token": "nested_tok"}}}')
        assert t._extract_token(resp, "data.auth.token") == "nested_tok"

    def test_extracts_cookie_token(self):
        t = self._tester()
        resp = mock_response(200, "", headers={
            "content-type": "application/json",
            "Set-Cookie":   "session=abc123xyz; HttpOnly; Secure",
        })
        assert t._extract_token(resp, "cookie:session") == "abc123xyz"

    def test_extracts_jwt_from_raw_body(self):
        """Fallback: bare JWT somewhere in a non-JSON response body."""
        t   = self._tester()
        jwt = make_jwt({"alg": "HS256"}, {"sub": "1"}, "s")
        resp = mock_response(200, f"Your token is: {jwt}", headers={"content-type": "text/plain"})
        result = t._extract_token(resp, "token")
        assert result == jwt

    def test_returns_none_on_missing_field(self):
        t = self._tester()
        resp = mock_response(200, '{"other": "data"}')
        assert t._extract_token(resp, "token") is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Response-bypass tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestResponseBypass:
    def test_200_on_failed_login_flagged(self):
        """App returns 200 + 'invalid password' in body → medium finding."""
        session = MockSession({
            "/login":  mock_response(200, '{"message": "invalid password"}'),
            "/api/me": mock_response(401, ""),
        })
        tester = AuthTester(session, _make_target())
        tester.run_all()
        assert any("Response-Based" in f.title for f in tester.findings)

    def test_401_on_failed_login_not_flagged(self):
        """Correct app returns 401 → no response-bypass finding."""
        session = MockSession({
            "/login":  mock_response(401, '{"error": "invalid credentials"}'),
            "/api/me": mock_response(401, ""),
        })
        tester = AuthTester(session, _make_target())
        tester.run_all()
        assert not any("Response-Based" in f.title for f in tester.findings)

    def test_auth_boolean_fields_flagged(self):
        """Login response has {"success": false, "authenticated": false} → low finding."""
        body = json.dumps({"success": False, "authenticated": False, "token": None})
        session = MockSession({
            "/login":  mock_response(401, body),
            "/api/me": mock_response(401, ""),
        })
        tester = AuthTester(session, _make_target())
        tester.run_all()
        assert any("Boolean" in f.title for f in tester.findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Password reset reuse tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestResetReuse:
    def _setup(self, second_use_status: int):
        reset_token = "tok_RESETABC123"
        session = MockSession({
            "/login":           mock_response(200, '{"token":"dummy.dummy.dummy"}'),
            "/forgot-password": mock_response(200, json.dumps({"reset_token": reset_token})),
            "/reset-password":  mock_response(second_use_status, "{}"),
            "/api/me":          mock_response(401, ""),
        })
        target = _make_target(
            reset_endpoint         = "/forgot-password",
            reset_confirm_endpoint = "/reset-password",
            reset_test_email       = "test@wraith.local",
            token_extractor        = lambda resp: (
                resp.json().get("reset_token") if resp.is_json else None
            ),
        )
        return AuthTester(session, target)

    def test_reuse_detected_when_second_use_succeeds(self):
        tester = self._setup(second_use_status=200)
        tester.run_all()
        assert any("Not Invalidated" in f.title for f in tester.findings)

    def test_reuse_not_flagged_when_second_use_rejected(self):
        tester = self._setup(second_use_status=400)
        tester.run_all()
        assert not any("Not Invalidated" in f.title for f in tester.findings)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])