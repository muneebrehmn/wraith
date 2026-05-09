"""
specter/tests/test_phase4.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 4 tests — SessionAnalyzer (no real network)
Run: python -m pytest tests/test_phase4.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import base64
import hmac
import hashlib
from typing import Dict, List, Optional

from utils.http_client import HttpRequest, HttpResponse
from core.session_analyzer import SessionAnalyzer, SessionTarget
from models.findings import Severity


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Shared test infrastructure
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def mock_resp(status=200, body="{}", headers=None, req=None) -> HttpResponse:
    return HttpResponse(
        status_code = status,
        headers     = headers or {"content-type": "application/json"},
        body        = body,
        elapsed_ms  = 5.0,
        request     = req or HttpRequest("POST", "http://t/"),
    )


class MockSession:
    """Route-function based mock session."""
    def __init__(self, route_fn=None, routes=None):
        self.route_fn = route_fn
        self.routes   = routes or {}
        self.history  = []
        self.calls:   List[HttpRequest] = []

    def send(self, req: HttpRequest) -> HttpResponse:
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
        self.history.append(resp)
        return resp


def _target(**kwargs) -> SessionTarget:
    """Base target with sane defaults."""
    return SessionTarget(
        base_url           = "http://target.test",
        login_endpoint     = "/login",
        login_body         = '{"username":"u","password":"p"}',
        logout_endpoint    = "/logout",
        protected_endpoint = "/api/me",
        **kwargs,
    )


VALID_TOKEN = "a3f8c2d91e047b56af12e8cd490b37fe"   # realistic opaque token


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Post-Logout Token Reuse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPostLogoutReuse:

    def _session(self, token_valid_after_logout: bool):
        """
        Simulates a server where the token is or isn't invalidated after logout.
        Tracks whether logout was called using a mutable flag.
        """
        state = {"logged_out": False}

        def route(req: HttpRequest) -> HttpResponse:
            if "/login" in req.url:
                return mock_resp(200, json.dumps({"token": VALID_TOKEN}))

            if "/logout" in req.url:
                state["logged_out"] = True
                return mock_resp(200, '{"message":"logged out"}')

            if "/api/me" in req.url:
                # Vulnerable: always valid.   Secure: invalid after logout.
                if state["logged_out"] and not token_valid_after_logout:
                    return mock_resp(401, '{"error":"invalid token"}')
                return mock_resp(200, '{"user":"alice"}')

            return mock_resp(404)

        return MockSession(route_fn=route)

    def test_reuse_detected_on_vulnerable_app(self):
        session = self._session(token_valid_after_logout=True)
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        assert any("Post-Logout" in f.title for f in tester.findings)
        assert any(f.severity == Severity.HIGH for f in tester.findings
                   if "Post-Logout" in f.title)

    def test_reuse_not_flagged_on_secure_app(self):
        session = self._session(token_valid_after_logout=False)
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        assert not any("Post-Logout Token Reuse" == f.title for f in tester.findings)

    def test_skipped_when_logout_not_configured(self):
        """No logout_endpoint → check silently skipped, no crash."""
        session = MockSession(routes={"/login": mock_resp(200, json.dumps({"token": VALID_TOKEN}))})
        # Build target manually so logout_endpoint doesn't conflict with the helper default
        target  = SessionTarget(
            base_url           = "http://target.test",
            login_endpoint     = "/login",
            login_body         = '{"username":"u","password":"p"}',
            logout_endpoint    = "",           # explicitly disabled
            protected_endpoint = "/api/me",
        )
        tester  = SessionAnalyzer(session, target)
        tester.run_all()
        assert not any("Post-Logout Token Reuse" in f.title for f in tester.findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Session Fixation
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSessionFixation:

    def _session(self, echoes_fixed_id: bool):
        """
        echoes_fixed_id=True  → login response contains SPECTER_FIXATION_TEST in Set-Cookie
        echoes_fixed_id=False → login always returns a fresh token
        """
        FIXED = "SPECTER_FIXATION_TEST_12345"

        def route(req: HttpRequest) -> HttpResponse:
            if "/login" in req.url:
                if echoes_fixed_id:
                    # Vulnerable: echo back whatever was in the Cookie header
                    incoming_cookie = req.headers.get("Cookie", "")
                    if FIXED in incoming_cookie:
                        return mock_resp(200, '{"ok":true}', headers={
                            "content-type": "application/json",
                            "Set-Cookie": f"session={FIXED}; Path=/",
                        })
                # Secure: always issue a fresh random session
                return mock_resp(200, '{"ok":true}', headers={
                    "content-type": "application/json",
                    "Set-Cookie": f"session={VALID_TOKEN}; HttpOnly; Secure; SameSite=Strict",
                })

            if "/api/me" in req.url:
                # Only accept the known valid token, not the fixed ID
                auth = req.headers.get("Authorization", "") + req.headers.get("Cookie", "")
                if VALID_TOKEN in auth:
                    return mock_resp(200, '{"user":"alice"}')
                return mock_resp(401, '{"error":"invalid"}')

            return mock_resp(200)

        return MockSession(route_fn=route)

    def test_fixation_detected_via_echo(self):
        session = self._session(echoes_fixed_id=True)
        tester  = SessionAnalyzer(session, _target(login_token_field="cookie:session"))
        tester.run_all()
        assert any("Fixation" in f.title for f in tester.findings)

    def test_fixation_not_flagged_when_id_rotated(self):
        session = self._session(echoes_fixed_id=False)
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        fixation = [f for f in tester.findings if "Fixation" in f.title
                    and "Authenticated" in f.title]
        assert len(fixation) == 0


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Concurrent Session Abuse
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestConcurrentSessions:

    def _session(self, max_sessions: int):
        """
        max_sessions: how many sessions the server keeps valid simultaneously.
        On each new login, if total sessions > max_sessions, oldest is dropped.
        """
        issued:  List[str] = []   # ordered list of issued tokens (oldest first)
        counter: Dict[str, int] = {"n": 0}

        def route(req: HttpRequest) -> HttpResponse:
            if "/login" in req.url:
                # Issue a fresh unique token per login
                token = f"TOKEN_{counter['n']:04d}"
                counter["n"] += 1
                issued.append(token)
                # Evict oldest if over limit
                while len(issued) > max_sessions:
                    issued.pop(0)
                return mock_resp(200, json.dumps({"token": token}))

            if "/api/me" in req.url:
                auth  = req.headers.get("Authorization", "")
                cookie = req.headers.get("Cookie", "")
                token = auth.replace("Bearer ", "").strip() or cookie
                if token in issued:
                    return mock_resp(200, '{"user":"alice"}')
                return mock_resp(401, '{"error":"invalid or evicted token"}')

            return mock_resp(200)

        return MockSession(route_fn=route)

    def test_concurrent_flagged_when_no_limit(self):
        session = self._session(max_sessions=99)   # effectively unlimited
        tester  = SessionAnalyzer(session, _target(concurrent_session_count=3))
        tester.run_all()
        assert any("Concurrent" in f.title and "No " in f.title for f in tester.findings)

    def test_concurrent_not_flagged_when_limit_enforced(self):
        session = self._session(max_sessions=1)    # strict: only one session allowed
        tester  = SessionAnalyzer(session, _target(concurrent_session_count=3))
        tester.run_all()
        assert not any("No Concurrent Session Limit" == f.title for f in tester.findings)

    def test_newest_invalidated_flagged(self):
        """
        Directly tests the tester's _add_finding branch for newest-invalidated.
        Scenario: server issues 3 tokens, only the FIRST (oldest) stays valid,
        second and third are evicted. valid_count=1, newest not valid → LOW finding.

        We isolate this by running ONLY check_concurrent_sessions (not run_all),
        so other checks don't pollute the login sequence.
        """
        session_tokens: List[str] = []
        counter: Dict[str, int] = {"n": 0}

        def route(req: HttpRequest) -> HttpResponse:
            if "/login" in req.url:
                token = f"CONC_{counter['n']:04d}"
                counter["n"] += 1
                session_tokens.append(token)
                return mock_resp(200, json.dumps({"token": token}))

            if "/api/me" in req.url:
                auth  = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
                # Only the first issued token is valid (oldest kept, newest evicted)
                if session_tokens and auth == session_tokens[0]:
                    return mock_resp(200, '{"user":"alice"}')
                return mock_resp(401, '{"error":"evicted"}')

            return mock_resp(200)

        session = MockSession(route_fn=route)
        tester  = SessionAnalyzer(session, _target(concurrent_session_count=3))
        # Call only the concurrent check directly to avoid login pollution from other checks
        tester.check_concurrent_sessions()
        assert any("Newest Session Invalidated" in f.title for f in tester.findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# No Invalidation on Password Change
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPwChangeInvalidation:

    def _session(self, invalidates_on_change: bool):
        """
        invalidates_on_change=True  → after pw change, old tokens are rejected
        invalidates_on_change=False → old tokens still work after pw change (vulnerable)
        """
        state   = {"changed": False}
        issued: List[str] = []
        counter: Dict[str, int] = {"n": 0}

        def route(req: HttpRequest) -> HttpResponse:
            if "/login" in req.url:
                token = f"TOKEN_{counter['n']:04d}"
                counter["n"] += 1
                issued.append(token)
                return mock_resp(200, json.dumps({"token": token}))

            if "/change-password" in req.url:
                state["changed"] = True
                if invalidates_on_change:
                    # Keep only the most recent token (the one used to change pw)
                    if issued:
                        last = issued[-1]
                        issued.clear()
                        issued.append(last)
                return mock_resp(200, '{"message":"password changed"}')

            if "/api/me" in req.url:
                auth  = req.headers.get("Authorization", "").replace("Bearer ", "").strip()
                cookie = req.headers.get("Cookie", "")
                token  = auth or cookie
                if token in issued:
                    return mock_resp(200, '{"user":"alice"}')
                return mock_resp(401, '{"error":"invalid or invalidated token"}')

            return mock_resp(200)

        return MockSession(route_fn=route)

    def test_old_session_survives_pw_change_flagged(self):
        session = self._session(invalidates_on_change=False)
        tester  = SessionAnalyzer(session, _target(
            change_pw_endpoint = "/change-password",
            change_pw_body     = '{"old":"p","new":"NewP@ss1"}',
        ))
        tester.run_all()
        assert any("Not Invalidated After Password Change" in f.title for f in tester.findings)
        assert any(f.severity == Severity.HIGH for f in tester.findings
                   if "Not Invalidated" in f.title)

    def test_invalidation_on_pw_change_no_finding(self):
        session = self._session(invalidates_on_change=True)
        tester  = SessionAnalyzer(session, _target(
            change_pw_endpoint = "/change-password",
            change_pw_body     = '{"old":"p","new":"NewP@ss1"}',
        ))
        tester.run_all()
        assert not any("Not Invalidated After Password Change" in f.title for f in tester.findings)

    def test_skipped_when_not_configured(self):
        session = MockSession(routes={"/login": mock_resp(200, json.dumps({"token": VALID_TOKEN}))})
        tester  = SessionAnalyzer(session, _target())   # no change_pw_endpoint
        tester.run_all()
        assert not any("Password Change" in f.title and "Not Invalidated" in f.title
                       for f in tester.findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Cookie Flag Audit
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCookieFlags:

    def _session(self, set_cookie: str):
        def route(req: HttpRequest) -> HttpResponse:
            if "/login" in req.url:
                return mock_resp(200, '{"ok":true}', headers={
                    "content-type": "application/json",
                    "Set-Cookie": set_cookie,
                })
            return mock_resp(200)
        return MockSession(route_fn=route)

    def test_missing_httponly_flagged(self):
        session = self._session("session=abc123; Secure; SameSite=Strict")
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        assert any("HttpOnly" in f.title for f in tester.findings)

    def test_missing_secure_flagged(self):
        session = self._session("session=abc123; HttpOnly; SameSite=Lax")
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        assert any("Secure" in f.title for f in tester.findings)

    def test_missing_samesite_flagged(self):
        session = self._session("session=abc123; HttpOnly; Secure")
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        assert any("SameSite" in f.title for f in tester.findings)

    def test_secure_cookie_no_flag_findings(self):
        session = self._session("session=abc123; HttpOnly; Secure; SameSite=Strict")
        tester  = SessionAnalyzer(session, _target())
        tester.run_all()
        flag_findings = [f for f in tester.findings if "Cookie Flag" in f.title]
        assert len(flag_findings) == 0


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])