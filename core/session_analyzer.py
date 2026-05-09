"""
wraith/core/session_analyzer.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 4 – Session Analyzer

Covers all session attack vectors from the spec:
  1. Post-logout token reuse       — token still works after logout
  2. Session fixation               — server accepts attacker-supplied session ID
  3. Concurrent session abuse       — no limit on simultaneous sessions
  4. No invalidation on pw change   — old token survives a password change

How it fits:
  - Uses SpecterSession (http_client.py) for requests
  - Uses TokenAnalyzer (token_analyzer.py) to inspect session tokens
  - Emits ScanFinding objects (models/findings.py) for the reporter

Usage:
    from core.session_analyzer import SessionAnalyzer, SessionTarget
    from utils.http_client import make_session

    session = make_session(use_proxy=True)

    target = SessionTarget(
        base_url             = "https://target.com",
        login_endpoint       = "/api/login",
        login_body           = '{"username":"user","password":"pass"}',
        logout_endpoint      = "/api/logout",
        protected_endpoint   = "/api/me",
        change_pw_endpoint   = "/api/change-password",
        change_pw_body       = '{"old":"pass","new":"NewP@ss1"}',
        login_token_field    = "token",
    )

    analyzer = SessionAnalyzer(session, target)
    findings = analyzer.run_all()
"""

from __future__ import annotations

import json
import re
import time
import copy
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.http_client import SpecterSession, HttpRequest, HttpResponse
from utils.token_analyzer import TokenAnalyzer, audit_cookie_flags
from models.findings import ScanFinding, Severity, Category


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration dataclass
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class SessionTarget:
    """
    Describes the session management surface of the target application.
    Only configure what's relevant — unconfigured checks are skipped silently.
    """

    base_url: str                             # e.g. "https://target.com"

    # ── Login ────────────────────────────────────────────────────────────────
    login_endpoint:       str  = "/login"
    login_body:           str  = ""           # raw JSON credentials
    login_content_type:   str  = "application/json"

    # Where to find the issued session token in the login response.
    # Same syntax as AuthTarget: "token", "data.token", "cookie:session"
    login_token_field:    str  = "token"

    # ── Logout ───────────────────────────────────────────────────────────────
    logout_endpoint:      str  = "/logout"
    logout_method:        str  = "POST"       # some apps use GET /logout

    # ── Endpoint that requires a valid session ────────────────────────────────
    protected_endpoint:   str  = "/api/me"

    # ── Password change ───────────────────────────────────────────────────────
    change_pw_endpoint:   str  = ""
    change_pw_body:       str  = ""           # must produce a successful password change
    change_pw_method:     str  = "POST"

    # ── Concurrent session test ───────────────────────────────────────────────
    # How many parallel sessions to open before checking if the server enforces a limit
    concurrent_session_count: int = 3

    # ── Cookie names to audit for security flags ──────────────────────────────
    # Leave empty to auto-detect from Set-Cookie headers
    session_cookie_names: List[str] = field(default_factory=list)

    # ── Optional custom token extractor ──────────────────────────────────────
    token_extractor: Optional[Callable[[HttpResponse], Optional[str]]] = None

    # ── Extra headers sent with every request ────────────────────────────────
    extra_headers: Dict[str, str] = field(default_factory=dict)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SessionAnalyzer — main class
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SessionAnalyzer:
    """
    Probes session management vulnerabilities.

    Each check:
      1. Obtains one or more valid sessions via login
      2. Performs the relevant action (logout / pw-change / concurrent login)
      3. Tests whether old tokens are still accepted by the protected endpoint
      4. Emits ScanFinding objects if the server fails to invalidate them
    """

    def __init__(self, session: SpecterSession, target: SessionTarget):
        self.session  = session
        self.target   = target
        self.analyzer = TokenAnalyzer()
        self.findings: List[ScanFinding] = []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Public entry point
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def run_all(self) -> List[ScanFinding]:
        """Run every session check and return aggregated findings."""
        self.findings = []

        checks = [
            ("Post-Logout Token Reuse",          self.check_post_logout_reuse),
            ("Session Fixation",                  self.check_session_fixation),
            ("Concurrent Session Abuse",          self.check_concurrent_sessions),
            ("No Invalidation on Password Change",self.check_pw_change_invalidation),
            ("Session Cookie Flag Audit",         self.check_cookie_flags),
        ]

        for name, fn in checks:
            print(f"[*] Session: {name}")
            try:
                fn()
            except Exception as e:
                print(f"[!] {name} raised: {e}")
                self._add_finding(
                    title       = f"Check Error: {name}",
                    severity    = Severity.INFO,
                    description = str(e),
                    evidence    = {"exception": str(e)},
                )

        print(f"[+] Session phase complete — {len(self.findings)} findings")
        return self.findings

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 1 — Post-Logout Token Reuse
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_post_logout_reuse(self):
        """
        Tests whether a token remains usable after the user logs out.

        Attack flow:
          1. Login → capture token A
          2. Confirm token A works on the protected endpoint (baseline)
          3. Call the logout endpoint (with token A in the header)
          4. Re-use token A on the protected endpoint
          5. If step 4 returns 200 → server-side session was never invalidated

        This is a common bug in stateless JWT apps where the server only checks
        the signature but never maintains a token blocklist/denylist.
        """
        if not self.target.logout_endpoint:
            return

        # Step 1 & 2: login and confirm the token works
        token, login_resp = self._fresh_login()
        if not token:
            return

        baseline = self._probe(token)
        if not self._is_success(baseline):
            # Token didn't work even before logout — skip, probably misconfigured
            self._add_finding(
                title       = "Post-Logout Check: Baseline Probe Failed",
                severity    = Severity.INFO,
                description = "Token obtained from login was rejected before logout — check config.",
                evidence    = {"status": baseline.status_code, "body": baseline.body[:200]},
                tags        = ["session", "config"],
            )
            return

        # Step 3: logout
        logout_resp = self._request(
            self.target.logout_method,
            self.target.logout_endpoint,
            token = token,
        )

        # Step 4: probe with the same token post-logout
        post_logout_resp = self._probe(token)

        if self._is_success(post_logout_resp):
            self._add_finding(
                title       = "Post-Logout Token Reuse",
                severity    = Severity.HIGH,
                description = (
                    "The session token remained valid after calling the logout endpoint. "
                    "An attacker who steals a token (XSS, network sniff, shoulder surf) "
                    "can continue using it even after the legitimate user has logged out."
                ),
                evidence    = {
                    "token_prefix":        token[:30] + "...",
                    "logout_status":       logout_resp.status_code,
                    "post_logout_status":  post_logout_resp.status_code,
                    "post_logout_snippet": post_logout_resp.body[:300],
                },
                cwe         = 613,
                remediation = (
                    "Maintain a server-side session store or token denylist. "
                    "On logout, immediately invalidate the session/token server-side. "
                    "For JWTs, use short expiry + a Redis-backed denylist, or switch to opaque tokens."
                ),
                request  = post_logout_resp.request,
                response = post_logout_resp,
                tags     = ["session", "post-logout", "token-reuse"],
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 2 — Session Fixation
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_session_fixation(self):
        """
        Tests whether the server accepts an attacker-supplied session ID
        and promotes it to an authenticated session after login.

        Classic attack flow:
          1. Attacker sends the victim a link with a known session ID:
             ?sessionid=ATTACKER_KNOWN_VALUE  or  Cookie: session=ATTACKER_KNOWN_VALUE
          2. Victim logs in using that session ID
          3. If the server uses the same ID post-login (instead of rotating it),
             the attacker's known session ID is now authenticated

        What we test:
          a) Pre-login: inject a known fake session ID into the login request
          b) Post-login: check if the server returned the SAME session ID
             (rotation means a different, fresh ID should be issued)
          c) Attempt to use the injected ID to access the protected endpoint

        Variants tested:
          - Cookie injection:       Cookie: session=SPECTER_FIXED_ID
          - Query param injection:  POST /login?sessionid=SPECTER_FIXED_ID
          - Body field injection:   {"sessionid": "SPECTER_FIXED_ID", ...}
        """
        FIXED_ID = "SPECTER_FIXATION_TEST_12345"

        # ── Variant A: Cookie-based fixation ──────────────────────────────────
        self._check_fixation_variant(
            label        = "Cookie-based session fixation",
            fixed_id     = FIXED_ID,
            inject_via   = "cookie",
        )

        # ── Variant B: Query parameter fixation ───────────────────────────────
        self._check_fixation_variant(
            label        = "Query-param session fixation",
            fixed_id     = FIXED_ID,
            inject_via   = "queryparam",
        )

    def _check_fixation_variant(self, label: str, fixed_id: str, inject_via: str):
        """
        Performs a single fixation variant check.

        inject_via: "cookie" | "queryparam"
        """
        # Build the login request with the injected fixed session ID
        extra_headers = {}
        url_suffix    = ""

        if inject_via == "cookie":
            # Inject the fixed ID as a cookie in the login request
            extra_headers["Cookie"] = f"session={fixed_id}; sessionid={fixed_id}; PHPSESSID={fixed_id}"
        elif inject_via == "queryparam":
            # Append the ID as common query param names
            url_suffix = f"?sessionid={fixed_id}&session={fixed_id}&JSESSIONID={fixed_id}"

        # Send the login with the injected session ID
        login_url  = self.target.base_url + self.target.login_endpoint + url_suffix
        login_resp = self.session.send(HttpRequest(
            method  = "POST",
            url     = login_url,
            headers = {
                "Content-Type": self.target.login_content_type,
                **self.target.extra_headers,
                **extra_headers,
            },
            body = self.target.login_body,
        ))

        if login_resp.status_code >= 400:
            return   # login failed — can't evaluate fixation

        # Extract the session ID the server issued post-login
        issued_token = self._extract_token(login_resp)
        if not issued_token:
            return

        # ── Check 1: did the server echo back our fixed ID? ───────────────────
        # If the issued token IS our fixed ID, fixation is trivially confirmed
        if fixed_id in issued_token or fixed_id in (login_resp.header("Set-Cookie") or ""):
            self._add_finding(
                title       = f"Session Fixation: {label}",
                severity    = Severity.HIGH,
                description = (
                    f"Server issued the same session ID ({fixed_id[:20]}...) "
                    "that was supplied in the login request. "
                    "An attacker who plants a known session ID can hijack the session "
                    "after the victim authenticates."
                ),
                evidence    = {
                    "fixed_id":       fixed_id,
                    "issued_token":   issued_token[:40],
                    "inject_method":  inject_via,
                    "login_status":   login_resp.status_code,
                },
                cwe         = 384,
                remediation = (
                    "Always issue a new, randomly-generated session ID after successful login. "
                    "Invalidate any pre-login session ID."
                ),
                request  = login_resp.request,
                response = login_resp,
                tags     = ["session", "fixation"],
            )
            return

        # ── Check 2: can our fixed ID access the protected endpoint? ──────────
        # Even if not echoed back, some servers link the fixed ID to the new session
        probe_resp = self._probe(fixed_id)
        if self._is_success(probe_resp):
            self._add_finding(
                title       = f"Session Fixation: Fixed ID Authenticated ({label})",
                severity    = Severity.CRITICAL,
                description = (
                    f"After login, the pre-supplied session ID '{fixed_id[:20]}' "
                    "was accepted by the protected endpoint. "
                    "The server linked the victim's authenticated session to the "
                    "attacker-chosen identifier."
                ),
                evidence    = {
                    "fixed_id":      fixed_id,
                    "probe_status":  probe_resp.status_code,
                    "inject_method": inject_via,
                },
                cwe         = 384,
                remediation = (
                    "Regenerate the session ID on every privilege level change "
                    "(login, role change, sudo). Use session_regenerate_id() or equivalent."
                ),
                request  = probe_resp.request,
                response = probe_resp,
                tags     = ["session", "fixation", "critical"],
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 3 — Concurrent Session Abuse
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_concurrent_sessions(self):
        """
        Tests whether the server enforces limits on simultaneous sessions.

        Steps:
          1. Login N times to obtain N distinct tokens
          2. Verify all N tokens are still valid (none were invalidated by a newer login)
          3. If all tokens work simultaneously → no concurrent session limit

        Also checks:
          - Whether token 1 (oldest) is invalidated when token N (newest) logs in
            (some apps only keep the most recent session — acceptable policy)
          - Whether all tokens from the same user share the same expiry/claims

        Why it matters:
          No concurrent session limit makes credential-stuffing attacks more dangerous —
          an attacker who compromises creds can maintain persistent parallel access
          without triggering single-session-enforcement that would kick out the real user.
        """
        n = self.target.concurrent_session_count
        if n < 2:
            return

        # Gather N tokens from separate logins
        tokens: List[Tuple[str, HttpResponse]] = []
        for i in range(n):
            token, login_resp = self._fresh_login()
            if token:
                tokens.append((token, login_resp))
            time.sleep(0.2)   # small gap to get distinct timestamps

        if len(tokens) < 2:
            return   # couldn't gather enough sessions

        # Probe each token against the protected endpoint
        results: List[Tuple[str, HttpResponse]] = []
        for token, _ in tokens:
            probe = self._probe(token)
            results.append((token, probe))

        valid_count   = sum(1 for _, r in results if self._is_success(r))
        invalid_count = len(results) - valid_count

        if valid_count == len(tokens):
            # Every token is still valid → no session limit enforced
            self._add_finding(
                title       = "No Concurrent Session Limit",
                severity    = Severity.MEDIUM,
                description = (
                    f"All {n} sessions opened simultaneously remained valid. "
                    "The application does not enforce a maximum concurrent session policy. "
                    "An attacker with stolen credentials can maintain persistent parallel "
                    "access without alerting the legitimate user."
                ),
                evidence    = {
                    "sessions_tested":  n,
                    "sessions_valid":   valid_count,
                    "token_prefixes":   [t[:20] + "..." for t, _ in tokens],
                },
                cwe         = 613,
                remediation = (
                    "Enforce a maximum concurrent session limit (e.g., 1–3) per user. "
                    "When a new login exceeds the limit, invalidate the oldest session "
                    "and notify the user."
                ),
                tags = ["session", "concurrent", "credential-abuse"],
            )

        elif valid_count == 1 and invalid_count == n - 1:
            # Only the most recent token works — single-session policy is enforced
            # This is acceptable but worth noting (some apps do this wrong — kick newest, keep oldest)
            newest_valid = self._is_success(results[-1][1])
            if not newest_valid:
                self._add_finding(
                    title       = "Concurrent Session: Newest Session Invalidated (Not Oldest)",
                    severity    = Severity.LOW,
                    description = (
                        "The application enforces a single-session policy but invalidates "
                        "the newest login instead of the oldest. An attacker who logs in "
                        "after the victim can lock the victim out."
                    ),
                    evidence    = {
                        "newest_valid": newest_valid,
                        "oldest_valid": self._is_success(results[0][1]),
                    },
                    cwe         = 613,
                    remediation = (
                        "When enforcing single-session policy, invalidate the OLDEST session "
                        "to allow the current user to stay active."
                    ),
                    tags = ["session", "concurrent", "lockout"],
                )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 4 — No Invalidation on Password Change
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_pw_change_invalidation(self):
        """
        Tests whether existing sessions are invalidated when the password changes.

        Attack scenario:
          - Attacker compromises session A (e.g., via XSS or stolen token)
          - Victim notices and changes their password
          - If session A still works → attacker retains persistent access despite the pw change

        Steps:
          1. Login twice → tokens A (old) and B (current)
          2. Use token B to change the password
          3. Probe token A → should be invalidated
          4. Probe token B → may or may not be invalidated (app-dependent)
        """
        if not (self.target.change_pw_endpoint and self.target.change_pw_body):
            return

        # Step 1: open two sessions
        token_a, _ = self._fresh_login()   # "old" session — simulates attacker's stolen token
        time.sleep(0.3)
        token_b, _ = self._fresh_login()   # "current" session — victim's active session

        if not token_a or not token_b:
            return

        # Confirm both work before the change
        baseline_a = self._probe(token_a)
        baseline_b = self._probe(token_b)

        if not self._is_success(baseline_a) or not self._is_success(baseline_b):
            return   # one or both tokens didn't work — skip

        # Step 2: change password using token B (the "current" session)
        change_resp = self._request(
            self.target.change_pw_method,
            self.target.change_pw_endpoint,
            token = token_b,
            body  = self.target.change_pw_body,
        )

        if change_resp.status_code >= 400:
            # Password change failed — can't evaluate session invalidation
            self._add_finding(
                title       = "PW Change Invalidation: Password Change Request Failed",
                severity    = Severity.INFO,
                description = (
                    f"Password change endpoint returned {change_resp.status_code}. "
                    "Session invalidation check skipped. Verify change_pw_body config."
                ),
                evidence    = {"response": change_resp.body[:200]},
                tags        = ["session", "pw-change", "config"],
            )
            return

        # Step 3: probe token A (old session) — should be dead
        post_change_a = self._probe(token_a)

        # Step 4: probe token B (changing session) — policy varies
        post_change_b = self._probe(token_b)

        if self._is_success(post_change_a):
            self._add_finding(
                title       = "Session Not Invalidated After Password Change",
                severity    = Severity.HIGH,
                description = (
                    "An existing session (token A) remained valid after the account password "
                    "was changed from a different session (token B). "
                    "An attacker with a stolen session token retains access even after "
                    "the victim resets their password."
                ),
                evidence    = {
                    "token_a_prefix":       token_a[:30] + "...",
                    "token_b_prefix":       token_b[:30] + "...",
                    "pw_change_status":     change_resp.status_code,
                    "post_change_a_status": post_change_a.status_code,
                    "post_change_b_status": post_change_b.status_code,
                },
                cwe         = 613,
                remediation = (
                    "On any password change, invalidate ALL existing sessions for that user "
                    "except optionally the current one. "
                    "If using JWTs, maintain a per-user token generation counter — "
                    "tokens issued before the latest counter value are rejected."
                ),
                request  = post_change_a.request,
                response = post_change_a,
                tags     = ["session", "pw-change", "token-reuse"],
            )

        # Informational: note whether the current session survived too
        if self._is_success(post_change_b):
            self._add_finding(
                title       = "Current Session Survives Password Change (Verify Intent)",
                severity    = Severity.INFO,
                description = (
                    "The session used to perform the password change (token B) remained valid "
                    "afterwards. This may be intentional (keeping the user logged in). "
                    "Confirm this is by design — some security policies require all sessions "
                    "including the current one to be invalidated on password change."
                ),
                evidence    = {
                    "token_b_still_valid": True,
                    "post_change_status":  post_change_b.status_code,
                },
                tags = ["session", "pw-change", "informational"],
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 5 — Session Cookie Flag Audit
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_cookie_flags(self):
        """
        Audits Set-Cookie headers from the login response for missing security flags.
        Delegates per-cookie analysis to TokenAnalyzer.audit_cookie_flags() from Phase 1.

        Checks per cookie:
          - HttpOnly  (XSS can't steal it)
          - Secure    (only sent over HTTPS)
          - SameSite  (CSRF protection)
          - SameSite=None without Secure (dangerous combo)
        """
        # Perform a fresh login and collect all Set-Cookie headers
        _, login_resp = self._fresh_login()
        if not login_resp:
            return

        # Collect all Set-Cookie headers (may have multiple)
        set_cookie_headers = self._collect_set_cookie_headers(login_resp)

        if not set_cookie_headers:
            return   # no cookies — app may be token-only, skip silently

        for cookie_header in set_cookie_headers:
            # Skip non-session cookies (assets, tracking, etc.)
            # unless the user configured specific names to check
            if self.target.session_cookie_names:
                cookie_name = cookie_header.split("=")[0].strip()
                if cookie_name not in self.target.session_cookie_names:
                    continue

            # Use the Phase 1 cookie auditor
            audit = audit_cookie_flags(cookie_header)

            for flag_finding in audit.findings:
                # Map token_analyzer Severity → models Severity
                sev = Severity(flag_finding.severity.value)
                self._add_finding(
                    title       = f"Cookie Flag: {flag_finding.title} [{audit.name}]",
                    severity    = sev,
                    description = flag_finding.description,
                    evidence    = {
                        "cookie_name":   audit.name,
                        "cookie_flags":  audit.flags,
                        "raw_header":    cookie_header[:200],
                        **flag_finding.evidence,
                    },
                    cwe         = flag_finding.cwe,
                    remediation = flag_finding.remediation,
                    tags        = ["session", "cookie", "flags"],
                )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Internal helpers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _fresh_login(self) -> Tuple[Optional[str], Optional[HttpResponse]]:
        """
        Performs a login POST and returns (token, login_response).
        Returns (None, None) if login fails or token can't be extracted.
        """
        if not self.target.login_body:
            return None, None

        resp = self.session.send(HttpRequest(
            method  = "POST",
            url     = self.target.base_url + self.target.login_endpoint,
            headers = {
                "Content-Type": self.target.login_content_type,
                **self.target.extra_headers,
            },
            body = self.target.login_body,
        ))

        token = None
        if self.target.token_extractor:
            token = self.target.token_extractor(resp)
        else:
            token = self._extract_token(resp)

        return token, resp

    def _extract_token(self, resp: HttpResponse) -> Optional[str]:
        """
        Extract a token from a response using the configured field path.
        Supports: JSON dot-path, cookie:name, bare JWT fallback.
        (Same logic as auth_tester._extract_token — kept local to avoid coupling.)
        """
        field_path = self.target.login_token_field

        # Cookie extraction: "cookie:session"
        if field_path.startswith("cookie:"):
            cookie_name = field_path.split(":", 1)[1]
            set_cookie  = resp.header("Set-Cookie") or ""
            match = re.search(rf"{re.escape(cookie_name)}=([^;]+)", set_cookie)
            return match.group(1) if match else None

        # JSON dot-path extraction: "data.token"
        if resp.is_json:
            try:
                data = resp.json()
                for key in field_path.split("."):
                    data = data.get(key) if isinstance(data, dict) else None
                return str(data) if data else None
            except (json.JSONDecodeError, AttributeError):
                pass

        # Fallback: find a bare JWT in the body
        match = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", resp.body)
        return match.group(0) if match else None

    def _probe(self, token: str) -> HttpResponse:
        """
        Sends a GET to the protected endpoint using the given token.
        Injects as Bearer header (for JWTs) or as Cookie (for opaque tokens).
        """
        is_jwt = token.count(".") == 2 and token.startswith("eyJ")
        headers = {**self.target.extra_headers}

        if is_jwt:
            headers["Authorization"] = f"Bearer {token}"
        else:
            headers["Authorization"] = f"Bearer {token}"
            headers["Cookie"]        = f"session={token}; sessionid={token}"

        return self.session.send(HttpRequest(
            method  = "GET",
            url     = self.target.base_url + self.target.protected_endpoint,
            headers = headers,
        ))

    def _request(
        self,
        method:   str,
        endpoint: str,
        token:    str  = "",
        body:     str  = "",
        extra_headers: Optional[Dict] = None,
    ) -> HttpResponse:
        """General-purpose authenticated request to the target."""
        headers = {
            "Content-Type": "application/json",
            **self.target.extra_headers,
            **(extra_headers or {}),
        }

        if token:
            is_jwt = token.count(".") == 2 and token.startswith("eyJ")
            if is_jwt:
                headers["Authorization"] = f"Bearer {token}"
            else:
                headers["Authorization"] = f"Bearer {token}"
                headers["Cookie"]        = f"session={token}"

        return self.session.send(HttpRequest(
            method  = method.upper(),
            url     = self.target.base_url + endpoint,
            headers = headers,
            body    = body or None,
        ))

    def _is_success(self, resp: HttpResponse) -> bool:
        """
        Heuristic: True if the response looks like an authenticated success.
        Checks status 200 and absence of rejection keywords in the body.
        """
        if resp.status_code != 200:
            return False
        rejection = [
            "unauthorized", "unauthenticated", "invalid token", "token expired",
            "access denied", "forbidden", "not logged in", "session expired",
        ]
        body_lower = resp.body.lower()
        return not any(k in body_lower for k in rejection)

    def _collect_set_cookie_headers(self, resp: HttpResponse) -> List[str]:
        """
        Extracts all Set-Cookie header values from a response.
        requests collapses multiple Set-Cookie headers into one comma-joined string —
        we split them back out correctly by detecting cookie boundaries.
        """
        raw = resp.header("Set-Cookie") or ""
        if not raw:
            return []

        # Split on ", " only when followed by a token= pattern (cookie name start)
        # Simple split on newlines covers most cases from raw HTTP responses
        if "\n" in raw:
            return [line.strip() for line in raw.splitlines() if "=" in line]

        # For single cookies or comma-joined (requests behaviour), return as-is
        # More sophisticated splitting would need a full cookie parser
        return [raw] if "=" in raw else []

    def _add_finding(
        self,
        title:       str,
        severity:    Severity,
        description: str,
        evidence:    Optional[Dict[str, Any]] = None,
        cwe:         Optional[int]            = None,
        remediation: str                      = "",
        request:     Any                      = None,
        response:    Any                      = None,
        tags:        Optional[List[str]]      = None,
    ):
        """Construct a ScanFinding and append it to self.findings."""
        self.findings.append(ScanFinding(
            title       = title,
            severity    = severity,
            category    = Category.SESSION,
            description = description,
            evidence    = evidence or {},
            cwe         = cwe,
            remediation = remediation,
            request     = request,
            response    = response,
            phase       = "session",
            tags        = tags or [],
        ))