"""
wraith/tests/test_phase6.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 6 tests — Burp extension bundled logic
Tests all check functions without needing Burp present.
Run: python -m pytest tests/test_phase6.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import base64
import hmac
import hashlib
import time
from typing import List

# Import from the extension directly (BURP_AVAILABLE will be False in test env)
from burp_extension.authlogic_burp import (
    BurpRequest, BurpResponse, WraithScanRunner,
    check_jwt_none_alg, check_jwt_alg_confusion,
    check_post_logout_reuse, check_session_fixation,
    check_pw_change_invalidation, check_response_bypass,
    check_reset_token_reuse,
    _do_login, _extract_token, _probe, _is_jwt,
    SEV_CRITICAL, SEV_HIGH, SEV_MEDIUM, SEV_INFO,
    make_finding,
)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Mock HTTP adapter (no real network)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def mock_resp(status=200, body="{}", headers=None, req=None):
    return BurpResponse(
        status_code = status,
        headers     = headers or {"content-type": "application/json"},
        body        = body,
        elapsed_ms  = 5.0,
        request     = req or BurpRequest("GET", "http://t/"),
    )


class MockAdapter(object):
    """Scriptable mock adapter — route_fn(BurpRequest) → BurpResponse."""
    def __init__(self, route_fn=None, routes=None):
        self.route_fn = route_fn
        self.routes   = routes or {}
        self.calls    = []

    def send(self, req):
        self.calls.append(req)
        if self.route_fn:
            resp = self.route_fn(req)
        else:
            resp = None
            for path, r in self.routes.items():
                if path in req.url:
                    resp = r
                    break
            resp = resp or mock_resp()
        resp.request = req
        return resp


# ── JWT factory ───────────────────────────────────────────────────

def _b64e(d):
    return base64.urlsafe_b64encode(
        json.dumps(d, separators=(",", ":")).encode("utf-8")
    ).rstrip(b"=").decode("utf-8")


def make_jwt(header, payload, secret="", alg="HS256"):
    h = _b64e(header)
    p = _b64e(payload)
    if alg.upper() == "NONE" or not secret:
        return "{0}.{1}.".format(h, p)
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384}[alg.upper()]
    sig = hmac.new(secret.encode(), "{0}.{1}".format(h, p).encode(), fn).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=").decode("utf-8")
    return "{0}.{1}.{2}".format(h, p, sig_b64)


VALID_JWT = make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "exp": 9999999999}, "secret")
VALID_TOKEN = "a3f8c2d91e047b56ab12cd34ef56ab78"  # opaque token

BASE_CONFIG = {
    "base_url":           "http://target.test",
    "login_endpoint":     "/login",
    "login_body":         json.dumps({"username": "admin", "password": "admin"}),
    "token_field":        "token",
    "logout_endpoint":    "/logout",
    "protected_endpoint": "/api/me",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BurpRequest / BurpResponse model tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestModels:
    def test_response_is_success_200(self):
        r = mock_resp(200, '{"user":"alice"}')
        assert r.is_success

    def test_response_not_success_401(self):
        r = mock_resp(401, '{"error":"unauthorized"}')
        assert not r.is_success

    def test_response_not_success_200_with_rejection_keyword(self):
        r = mock_resp(200, '{"message":"invalid token"}')
        assert not r.is_success

    def test_response_is_json(self):
        r = mock_resp(200, '{}', headers={"content-type": "application/json"})
        assert r.is_json

    def test_response_not_json(self):
        r = mock_resp(200, "hello", headers={"content-type": "text/plain"})
        assert not r.is_json

    def test_response_header_case_insensitive(self):
        r = mock_resp(200, "{}", headers={"Content-Type": "application/json"})
        assert r.header("content-type") == "application/json"

    def test_response_contains(self):
        r = mock_resp(200, "invalid password")
        assert r.contains("invalid")
        assert not r.contains("success")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Token extraction
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestTokenExtraction:
    def test_json_top_level(self):
        r = mock_resp(200, json.dumps({"token": "abc123"}))
        assert _extract_token(r, "token") == "abc123"

    def test_json_dotpath(self):
        r = mock_resp(200, json.dumps({"data": {"auth": {"token": "nested"}}}))
        assert _extract_token(r, "data.auth.token") == "nested"

    def test_cookie_extraction(self):
        r = mock_resp(200, "{}", headers={
            "content-type": "application/json",
            "Set-Cookie":   "session=tok_abc123; HttpOnly; Secure",
        })
        assert _extract_token(r, "cookie:session") == "tok_abc123"

    def test_bare_jwt_fallback(self):
        r = mock_resp(200, "Your token is: " + VALID_JWT, headers={"content-type": "text/plain"})
        assert _extract_token(r, "token") == VALID_JWT

    def test_missing_field_returns_none(self):
        r = mock_resp(200, json.dumps({"other": "data"}))
        assert _extract_token(r, "token") is None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JWT none-alg
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestNoneAlg:
    def _adapter(self, protected_status=200, protected_body='{"user":"admin"}'):
        def route(req):
            if "/api/me" in req.url:
                return mock_resp(protected_status, protected_body)
            return mock_resp(200)
        return MockAdapter(route_fn=route)

    def test_none_alg_detected_on_vulnerable_app(self):
        adapter  = self._adapter(protected_status=200)
        findings = check_jwt_none_alg(adapter, BASE_CONFIG, VALID_JWT)
        assert any("None-Algorithm" in f["title"] for f in findings)
        assert any(f["severity"] == SEV_CRITICAL for f in findings)

    def test_none_alg_not_flagged_on_secure_app(self):
        adapter  = self._adapter(protected_status=401, protected_body='{"error":"unauthorized"}')
        findings = check_jwt_none_alg(adapter, BASE_CONFIG, VALID_JWT)
        assert len(findings) == 0

    def test_skipped_for_non_jwt_token(self):
        adapter  = self._adapter()
        findings = check_jwt_none_alg(adapter, BASE_CONFIG, VALID_TOKEN)
        assert len(findings) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Post-logout reuse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPostLogout:
    def _adapter(self, token_valid_after_logout):
        state = {"logged_out": False}
        def route(req):
            if "/logout" in req.url:
                state["logged_out"] = True
                return mock_resp(200, '{"ok":true}')
            if "/api/me" in req.url:
                if state["logged_out"] and not token_valid_after_logout:
                    return mock_resp(401, '{"error":"invalid token"}')
                return mock_resp(200, '{"user":"alice"}')
            return mock_resp(200)
        return MockAdapter(route_fn=route)

    def test_reuse_detected_on_vulnerable_app(self):
        adapter  = self._adapter(token_valid_after_logout=True)
        findings = check_post_logout_reuse(adapter, BASE_CONFIG, VALID_TOKEN)
        assert any("Post-Logout" in f["title"] for f in findings)

    def test_reuse_not_flagged_on_secure_app(self):
        adapter  = self._adapter(token_valid_after_logout=False)
        findings = check_post_logout_reuse(adapter, BASE_CONFIG, VALID_TOKEN)
        assert len(findings) == 0

    def test_skipped_when_no_logout_endpoint(self):
        config   = dict(BASE_CONFIG, logout_endpoint="")
        adapter  = MockAdapter()
        findings = check_post_logout_reuse(adapter, config, VALID_TOKEN)
        assert len(findings) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Session fixation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSessionFixation:
    FIXED = "SPECTER_FIXATION_TEST_12345"

    def _adapter(self, echoes_fixed):
        def route(req):
            if "/login" in req.url:
                if echoes_fixed:
                    cookie_hdr = req.headers.get("Cookie", "")
                    if self.FIXED in cookie_hdr:
                        return mock_resp(200, '{"ok":true}', headers={
                            "content-type": "application/json",
                            "Set-Cookie":   "session={0}; Path=/".format(self.FIXED),
                        })
                return mock_resp(200, '{"ok":true}', headers={
                    "content-type": "application/json",
                    "Set-Cookie":   "session=fresh_random_tok; HttpOnly; Secure",
                })
            return mock_resp(200)
        return MockAdapter(route_fn=route)

    def test_fixation_detected_on_echo(self):
        adapter  = self._adapter(echoes_fixed=True)
        findings = check_session_fixation(adapter, BASE_CONFIG)
        assert any("Fixation" in f["title"] for f in findings)

    def test_fixation_not_flagged_when_id_rotated(self):
        adapter  = self._adapter(echoes_fixed=False)
        findings = check_session_fixation(adapter, BASE_CONFIG)
        assert len(findings) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Password change invalidation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPwChangeInvalidation:
    def _adapter(self, invalidates):
        issued = []
        counter = {"n": 0}
        def route(req):
            if "/login" in req.url:
                tok = "TOK_{0:04d}".format(counter["n"])
                counter["n"] += 1
                issued.append(tok)
                return mock_resp(200, json.dumps({"token": tok}))
            if "/change-password" in req.url:
                if invalidates and issued:
                    last = issued[-1]
                    issued[:] = [last]
                return mock_resp(200, '{"ok":true}')
            if "/api/me" in req.url:
                auth = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
                if auth in issued:
                    return mock_resp(200, '{"user":"alice"}')
                return mock_resp(401, '{"error":"invalid"}')
            return mock_resp(200)
        return MockAdapter(route_fn=route)

    def test_old_session_survives_flagged(self):
        config   = dict(BASE_CONFIG,
                        change_pw_endpoint="/change-password",
                        change_pw_body='{"old":"admin","new":"NewP@ss1"}')
        adapter  = self._adapter(invalidates=False)
        findings = check_pw_change_invalidation(adapter, config)
        assert any("Not Invalidated After Password Change" in f["title"] for f in findings)

    def test_invalidation_no_finding(self):
        config   = dict(BASE_CONFIG,
                        change_pw_endpoint="/change-password",
                        change_pw_body='{"old":"admin","new":"NewP@ss1"}')
        adapter  = self._adapter(invalidates=True)
        findings = check_pw_change_invalidation(adapter, config)
        assert not any("Not Invalidated After Password Change" in f["title"] for f in findings)

    def test_skipped_when_not_configured(self):
        adapter  = MockAdapter()
        findings = check_pw_change_invalidation(adapter, BASE_CONFIG)
        assert len(findings) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Response bypass
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestResponseBypass:
    def test_200_with_failure_body_flagged(self):
        adapter = MockAdapter(routes={"/login": mock_resp(200, '{"message":"invalid password"}')})
        findings = check_response_bypass(adapter, BASE_CONFIG)
        assert any("Response-Based" in f["title"] for f in findings)

    def test_401_not_flagged(self):
        adapter = MockAdapter(routes={"/login": mock_resp(401, '{"error":"bad creds"}')})
        findings = check_response_bypass(adapter, BASE_CONFIG)
        assert len(findings) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Scan runner (integration smoke test)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestScanRunner:
    def test_runner_completes_without_crash(self):
        """Full scan runner over a mock target — no Burp required."""
        state  = {"complete": False, "findings": []}
        events = []

        def route(req):
            if "/login"  in req.url: return mock_resp(200, json.dumps({"token": VALID_TOKEN}))
            if "/logout" in req.url: return mock_resp(200, '{"ok":true}')
            if "/api/me" in req.url: return mock_resp(200, '{"user":"alice"}')
            return mock_resp(200)

        adapter = MockAdapter(route_fn=route)
        config  = dict(BASE_CONFIG)

        runner = WraithScanRunner(
            adapter     = adapter,
            config      = config,
            on_finding  = lambda f: state["findings"].append(f),
            on_complete = lambda fs: state.update({"complete": True}),
            on_status   = lambda m: events.append(m),
        )
        runner.run()   # run synchronously in test

        assert state["complete"]
        assert isinstance(state["findings"], list)
        assert any("Scan complete" in e for e in events)

    def test_runner_stop_flag_respected(self):
        """Stopping the runner mid-scan should not raise exceptions."""
        state = {"complete": False}

        def route(req):
            return mock_resp(200, json.dumps({"token": VALID_TOKEN}))

        adapter = MockAdapter(route_fn=route)
        runner  = WraithScanRunner(
            adapter     = MockAdapter(route_fn=route),
            config      = BASE_CONFIG,
            on_complete = lambda fs: state.update({"complete": True}),
        )
        runner.stop()  # stop before run even starts
        runner.run()
        assert state["complete"]  # on_complete still called

    def test_make_finding_structure(self):
        """make_finding() must produce a dict with required keys."""
        f = make_finding(
            title       = "Test",
            severity    = SEV_HIGH,
            description = "desc",
            cwe         = 347,
            phase       = "auth",
            tags        = ["jwt"],
        )
        assert f["title"]    == "Test"
        assert f["severity"] == SEV_HIGH
        assert f["cwe"]      == 347
        assert "jwt" in f["tags"]


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])