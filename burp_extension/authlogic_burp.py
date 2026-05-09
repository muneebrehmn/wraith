# -*- coding: utf-8 -*-
"""
wraith/burp_extension/authlogic_burp.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Wraith — Burp Suite Extension (Jython, self-contained)

INSTALLATION
────────────
1. Open Burp Suite → Extender → Extensions → Add
2. Extension type: Python
3. Select this file
4. Done — "Wraith" tab appears in Burp's main tab bar

WHAT IT DOES
────────────
This extension runs Wraith's auth, logic, and session checks directly
inside Burp. It routes all HTTP traffic through Burp's own engine, so
you get full visibility in Proxy history, Repeater, etc.

Jython compatibility notes (Jython 2.7):
  - No f-strings → use .format() or % formatting
  - No secrets module → use java.security.SecureRandom
  - No dataclasses → plain classes with __init__
  - threading via java.lang.Thread or Python threading module
  - javax.swing for UI (runs on Burp's EDT via SwingUtilities.invokeLater)

ARCHITECTURE
────────────
  BurpExtender          — Burp entry point (IBurpExtender)
  SpecterTab            — Main UI tab (ITab)
  ScanConfigPanel       — Left panel: target config form
  ResultsPanel          — Right panel: findings table + detail view
  SpecterScanThread     — Background scan thread
  BurpHttpAdapter       — Bridges Burp's makeHttpRequest → Specter's HttpResponse
  [Bundled core logic]  — Inline ports of auth/logic/session checks (Jython-safe)
"""

# ── Standard library (available in Jython 2.7) ─────────────────────────────
import sys
import os
import json
import re
import math
import hmac
import time
import base64
import hashlib
import threading
import traceback
from collections import OrderedDict

# ── Java / Burp imports ────────────────────────────────────────────────────
# These are only available when loaded inside Burp Suite.
# The try/except lets us import this file in unit tests without Burp present.
try:
    from burp import IBurpExtender, ITab, IHttpListener, IContextMenuFactory
    from java.lang import Runnable, Thread
    from java.awt import BorderLayout, GridBagLayout, GridBagConstraints, Insets, Color, Font, Dimension
    from java.awt.event import ActionListener, MouseAdapter
    from javax.swing import (
        JPanel, JTabbedPane, JButton, JTextField, JLabel, JTextArea,
        JScrollPane, JTable, JCheckBox, JSplitPane, JComboBox, JPasswordField,
        SwingUtilities, BorderFactory, JOptionPane, UIManager,
        ListSelectionModel, JFileChooser, BoxLayout, Box, JProgressBar,
        SwingConstants, DefaultComboBoxModel
    )
    from javax.swing.table import DefaultTableModel, DefaultTableCellRenderer
    from javax.swing.border import TitledBorder
    from java.io import File
    BURP_AVAILABLE = True
except ImportError:
    # Running outside Burp (tests, linting) — stub out the Burp classes
    BURP_AVAILABLE = False
    class IBurpExtender(object): pass
    class ITab(object): pass
    class IHttpListener(object): pass


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 1 — Bundled core logic (Jython-safe inline ports)
#
# These are simplified, Jython-compatible versions of the core
# Specter modules. They share the same logic but avoid Python 3-only
# syntax (f-strings, dataclasses, walrus operator, etc.).
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# ── Severity constants ────────────────────────────────────────────

SEV_CRITICAL = "critical"
SEV_HIGH     = "high"
SEV_MEDIUM   = "medium"
SEV_LOW      = "low"
SEV_INFO     = "info"

SEV_SCORE = {
    SEV_CRITICAL: 5,
    SEV_HIGH:     4,
    SEV_MEDIUM:   3,
    SEV_LOW:      2,
    SEV_INFO:     1,
}

# ── Finding (plain dict-based, no dataclass) ──────────────────────

def make_finding(title, severity, description, evidence=None,
                 cwe=None, remediation="", phase="", tags=None,
                 request=None, response=None):
    """
    Creates a finding dict. All Specter checks return lists of these.
    Using a dict instead of a dataclass for Jython 2.7 compatibility.
    """
    return {
        "title":       title,
        "severity":    severity,
        "description": description,
        "evidence":    evidence or {},
        "cwe":         cwe,
        "remediation": remediation,
        "phase":       phase,
        "tags":        tags or [],
        "request":     request,
        "response":    response,
    }


# ── HTTP models ───────────────────────────────────────────────────

class BurpRequest(object):
    """Lightweight HTTP request wrapper — Jython-safe."""
    def __init__(self, method, url, headers=None, body=None):
        self.method  = method
        self.url     = url
        self.headers = headers or {}
        self.body    = body

    def clone(self, **overrides):
        import copy
        c = copy.deepcopy(self)
        for k, v in overrides.items():
            setattr(c, k, v)
        return c


class BurpResponse(object):
    """Lightweight HTTP response wrapper — Jython-safe."""
    def __init__(self, status_code, headers, body, elapsed_ms=0, request=None, error=None):
        self.status_code = status_code
        self.headers     = headers or {}
        self.body        = body or ""
        self.elapsed_ms  = elapsed_ms
        self.request     = request
        self.error       = error

    @property
    def is_json(self):
        ct = self.headers.get("content-type", self.headers.get("Content-Type", ""))
        return "application/json" in ct.lower()

    def json(self):
        return json.loads(self.body)

    def header(self, name):
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return None

    def contains(self, *substrings):
        body_lower = self.body.lower()
        return any(s.lower() in body_lower for s in substrings)

    @property
    def is_success(self):
        """Heuristic: authenticated success response."""
        if self.status_code != 200:
            return False
        rejection = [
            "unauthorized", "unauthenticated", "invalid token",
            "access denied", "forbidden", "token expired",
        ]
        return not self.contains(*rejection)


# ── BurpHttpAdapter ───────────────────────────────────────────────

class BurpHttpAdapter(object):
    """
    Routes Wraith's HTTP calls through Burp's makeHttpRequest engine.
    This means every request made by Wraith is visible in Burp Proxy
    history, can be intercepted, and appears in Burp's traffic log.

    Usage:
        adapter = BurpHttpAdapter(callbacks, helpers)
        resp = adapter.send(BurpRequest("GET", "https://target.com/api/me",
                                        headers={"Authorization": "Bearer ..."}))
    """

    def __init__(self, callbacks, helpers):
        # callbacks: IBurpExtenderCallbacks — Burp's main API object
        # helpers:   IExtensionHelpers      — Burp's HTTP helper methods
        self.callbacks = callbacks
        self.helpers   = helpers

    def send(self, req):
        """
        Converts a BurpRequest to Burp's byte[] format, sends it via
        makeHttpRequest, and wraps the response in a BurpResponse.
        """
        try:
            t0 = time.time()

            # Parse URL into host/port/protocol components
            parsed   = self._parse_url(req.url)
            host     = parsed["host"]
            port     = parsed["port"]
            use_https = parsed["https"]

            # Build raw HTTP request bytes using Burp's helpers
            raw_request = self._build_raw_request(req, parsed)

            # Create Burp's IHttpService
            http_service = self.helpers.buildHttpService(host, port, use_https)

            # Send via Burp — this goes through Proxy, Scanner, etc.
            http_message = self.callbacks.makeHttpRequest(http_service, raw_request)

            elapsed = (time.time() - t0) * 1000

            # Parse the response bytes Burp returns
            resp_bytes  = http_message.getResponse()
            if resp_bytes is None:
                return BurpResponse(0, {}, "", elapsed_ms=elapsed,
                                    request=req, error="no_response")

            analyzed    = self.helpers.analyzeResponse(resp_bytes)
            status_code = analyzed.getStatusCode()
            headers_raw = analyzed.getHeaders()
            body_offset = analyzed.getBodyOffset()

            # Convert Java List of header strings to a Python dict
            headers = {}
            for h in headers_raw:
                h_str = str(h)
                if ":" in h_str:
                    k, _, v = h_str.partition(":")
                    headers[k.strip()] = v.strip()

            # Decode body bytes
            body = ""
            if resp_bytes and len(resp_bytes) > body_offset:
                try:
                    body = self.helpers.bytesToString(resp_bytes[body_offset:])
                except Exception:
                    body = ""

            return BurpResponse(
                status_code = int(status_code),
                headers     = headers,
                body        = body,
                elapsed_ms  = elapsed,
                request     = req,
            )

        except Exception as e:
            return BurpResponse(
                status_code = 0,
                headers     = {},
                body        = "",
                elapsed_ms  = 0,
                request     = req,
                error       = str(e),
            )

    def _build_raw_request(self, req, parsed):
        """Build a raw HTTP request byte array in Burp's expected format."""
        path    = parsed["path"] or "/"
        host    = parsed["host"]
        port    = parsed["port"]
        method  = req.method.upper()

        # Merge in default headers
        headers = {
            "Host":            "{0}:{1}".format(host, port) if port not in (80, 443) else host,
            "User-Agent":      "Wraith/1.0 BurpExtension",
            "Accept":          "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Connection":      "close",
        }
        if req.headers:
            headers.update(req.headers)

        body_bytes = ""
        if req.body:
            body_bytes = req.body
            headers["Content-Length"] = str(len(req.body))

        # Assemble raw HTTP/1.1 request
        lines = ["{0} {1} HTTP/1.1".format(method, path)]
        for k, v in headers.items():
            lines.append("{0}: {1}".format(k, v))
        lines.append("")
        lines.append(body_bytes or "")

        raw = "\r\n".join(lines)
        return self.helpers.stringToBytes(raw)

    @staticmethod
    def _parse_url(url):
        """
        Minimal URL parser — avoids urllib.parse (not in Jython 2.7's stdlib path).
        Returns dict with host, port, path, https.
        """
        url = url.strip()
        https = url.lower().startswith("https")

        # Strip protocol
        if "://" in url:
            url = url.split("://", 1)[1]

        # Split host and path
        if "/" in url:
            host_part, path = url.split("/", 1)
            path = "/" + path
        else:
            host_part = url
            path = "/"

        # Handle port in host
        if ":" in host_part:
            host, port_str = host_part.rsplit(":", 1)
            port = int(port_str)
        else:
            host = host_part
            port = 443 if https else 80

        return {"host": host, "port": port, "path": path, "https": https}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 2 — Bundled check logic (Jython-safe)
#
# Each check_* function takes (adapter, config) and returns a list
# of finding dicts. Config is a plain Python dict built from the UI.
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _do_login(adapter, config):
    """
    Perform a login and return (token_string, response).
    Returns (None, response) if login fails or token can't be extracted.
    """
    if not config.get("login_body"):
        return None, None

    resp = adapter.send(BurpRequest(
        method  = "POST",
        url     = config["base_url"] + config.get("login_endpoint", "/login"),
        headers = {"Content-Type": "application/json"},
        body    = config["login_body"],
    ))

    token = _extract_token(resp, config.get("token_field", "token"))
    return token, resp


def _extract_token(resp, field_path):
    """
    Extract a token from a response.
    Supports: JSON dot-path ("data.token"), cookie ("cookie:session"),
    and bare JWT fallback.
    """
    if not resp or resp.status_code == 0:
        return None

    # Cookie extraction
    if field_path.startswith("cookie:"):
        name = field_path.split(":", 1)[1]
        sc   = resp.header("Set-Cookie") or ""
        m    = re.search(r"(?i)" + re.escape(name) + r"=([^;]+)", sc)
        return m.group(1) if m else None

    # JSON dot-path
    if resp.is_json:
        try:
            data = resp.json()
            for key in field_path.split("."):
                data = data.get(key) if isinstance(data, dict) else None
            return str(data) if data else None
        except Exception:
            pass

    # Bare JWT fallback
    m = re.search(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*", resp.body)
    return m.group(0) if m else None


def _probe(adapter, config, token):
    """GET the protected endpoint with the given token."""
    is_jwt = token.count(".") == 2 and token.startswith("eyJ")
    headers = {"Authorization": "Bearer " + token}
    if not is_jwt:
        headers["Cookie"] = "session=" + token + "; sessionid=" + token
    return adapter.send(BurpRequest(
        method  = "GET",
        url     = config["base_url"] + config.get("protected_endpoint", "/api/me"),
        headers = headers,
    ))


def _b64_decode_jwt(segment):
    """URL-safe base64 decode with padding fix — used for JWT parsing."""
    segment = segment.replace("-", "+").replace("_", "/")
    pad = 4 - len(segment) % 4
    if pad != 4:
        segment += "=" * pad
    return base64.b64decode(segment)


def _b64_encode_jwt(data):
    """URL-safe base64 encode without padding — used for JWT forging.
    Works in both Python 3 (tests) and Jython 2.7 (Burp).
    """
    encoded = base64.urlsafe_b64encode(data)
    # rstrip accepts bytes in Py3, str in Jython 2.7 — handle both
    if isinstance(encoded, bytes):
        return encoded.rstrip(b"=").decode("utf-8")
    return encoded.rstrip("=")


def _is_jwt(token):
    return isinstance(token, str) and token.count(".") == 2 and token.startswith("eyJ")


# ── Check: JWT none-alg ───────────────────────────────────────────

def check_jwt_none_alg(adapter, config, token):
    """
    Forges a JWT with alg=none and empty signature, then sends it to
    the protected endpoint. Reports finding if the server accepts it.
    """
    findings = []
    if not _is_jwt(token):
        return findings

    parts = token.split(".")
    try:
        header = json.loads(_b64_decode_jwt(parts[0]))
    except Exception:
        return findings

    for variant in ["none", "None", "NONE", "nOnE"]:
        header["alg"] = variant
        new_hdr = _b64_encode_jwt(
            json.dumps(header, separators=(",", ":")).encode("utf-8")
        )
        # Jython 2.7: new_hdr may be bytes, convert to str
        if isinstance(new_hdr, bytes):
            new_hdr = new_hdr.decode("utf-8")
        forged = "{0}.{1}.".format(new_hdr, parts[1])

        resp = _probe(adapter, config, forged)
        if resp.is_success:
            findings.append(make_finding(
                title       = "JWT None-Algorithm Bypass",
                severity    = SEV_CRITICAL,
                description = (
                    "Server accepted a JWT with alg='{0}' and no signature. "
                    "An attacker can forge arbitrary claims without knowing the signing secret."
                ).format(variant),
                evidence    = {
                    "alg_variant":     variant,
                    "forged_token":    forged[:80] + "...",
                    "response_status": resp.status_code,
                },
                cwe         = 347,
                remediation = "Reject tokens where alg=none. Enforce an algorithm allowlist server-side.",
                phase       = "auth",
                tags        = ["jwt", "none-alg", "auth-bypass"],
                request     = resp.request,
                response    = resp,
            ))
            break  # one confirmed finding is enough

    return findings


# ── Check: JWT algorithm confusion (RS256 → HS256) ───────────────

def check_jwt_alg_confusion(adapter, config, token, public_key_pem):
    """
    Attempts RS256→HS256 confusion attack by signing with public key as HMAC secret.
    Only runs if public_key_pem is provided in config.
    """
    findings = []
    if not _is_jwt(token) or not public_key_pem:
        return findings

    parts = token.split(".")
    try:
        header = json.loads(_b64_decode_jwt(parts[0]))
    except Exception:
        return findings

    header["alg"] = "HS256"
    new_hdr_b = json.dumps(header, separators=(",", ":")).encode("utf-8")
    new_hdr   = _b64_encode_jwt(new_hdr_b)
    if isinstance(new_hdr, bytes):
        new_hdr = new_hdr.decode("utf-8")

    signing_input = "{0}.{1}".format(new_hdr, parts[1]).encode("utf-8")
    secret        = public_key_pem.encode("utf-8")

    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = _b64_encode_jwt(sig)
    if isinstance(sig_b64, bytes):
        sig_b64 = sig_b64.decode("utf-8")

    forged = "{0}.{1}.{2}".format(new_hdr, parts[1], sig_b64)
    resp   = _probe(adapter, config, forged)

    if resp.is_success:
        findings.append(make_finding(
            title       = "JWT Algorithm Confusion (RS256 to HS256)",
            severity    = SEV_CRITICAL,
            description = (
                "Server accepted an HS256 token signed with the RS256 public key as the HMAC secret. "
                "An attacker who knows the public key can forge any JWT payload."
            ),
            evidence    = {"response_status": resp.status_code},
            cwe         = 347,
            remediation = "Enforce a strict algorithm allowlist. Never accept HS* on RS*-configured endpoints.",
            phase       = "auth",
            tags        = ["jwt", "alg-confusion"],
            request     = resp.request,
            response    = resp,
        ))

    return findings


# ── Check: password reset token reuse ────────────────────────────

def check_reset_token_reuse(adapter, config):
    """
    Triggers a password reset, uses the token once, then replays it.
    Requires reset_endpoint, reset_confirm_endpoint, reset_email in config.
    """
    findings = []
    reset_ep   = config.get("reset_endpoint", "")
    confirm_ep = config.get("reset_confirm_endpoint", "")
    email      = config.get("reset_email", "")

    if not (reset_ep and confirm_ep and email):
        return findings

    # Trigger reset
    trigger_resp = adapter.send(BurpRequest(
        method  = "POST",
        url     = config["base_url"] + reset_ep,
        headers = {"Content-Type": "application/json"},
        body    = json.dumps({"email": email}),
    ))

    # Try to extract reset token from response (app-dependent)
    reset_token = _extract_token(trigger_resp, config.get("reset_token_field", "token"))

    if not reset_token:
        findings.append(make_finding(
            title       = "Password Reset Token Reuse — Manual Verification Required",
            severity    = SEV_INFO,
            description = (
                "Reset endpoint responded but the token could not be extracted automatically. "
                "Manually use the token, then replay the same request to check for reuse."
            ),
            evidence    = {"trigger_status": trigger_resp.status_code},
            phase       = "auth",
            tags        = ["reset", "manual"],
        ))
        return findings

    new_pw = "Wraith_Test_P@ss1"
    body1  = json.dumps({"token": reset_token, "password": new_pw})

    use1 = adapter.send(BurpRequest(
        method  = "POST",
        url     = config["base_url"] + confirm_ep,
        headers = {"Content-Type": "application/json"},
        body    = body1,
    ))
    use2 = adapter.send(BurpRequest(
        method  = "POST",
        url     = config["base_url"] + confirm_ep,
        headers = {"Content-Type": "application/json"},
        body    = body1,
    ))

    if use1.status_code < 400 and use2.status_code < 400:
        findings.append(make_finding(
            title       = "Password Reset Token Not Invalidated After Use",
            severity    = SEV_HIGH,
            description = (
                "The reset token was accepted on a second submission after already being used. "
                "An attacker who intercepts the reset link can replay it later."
            ),
            evidence    = {
                "first_use_status":  use1.status_code,
                "second_use_status": use2.status_code,
            },
            cwe         = 613,
            remediation = "Invalidate reset tokens immediately after first use. Enforce a short expiry (15 min).",
            phase       = "auth",
            tags        = ["reset", "token-reuse"],
            request     = use2.request,
            response    = use2,
        ))

    return findings


# ── Check: post-logout token reuse ───────────────────────────────

def check_post_logout_reuse(adapter, config, token):
    """Logs out, then re-uses the old token to check if it still works."""
    findings = []
    logout_ep = config.get("logout_endpoint", "")
    if not logout_ep or not token:
        return findings

    # Baseline: confirm token works before logout
    baseline = _probe(adapter, config, token)
    if not baseline.is_success:
        return findings

    # Logout
    adapter.send(BurpRequest(
        method  = config.get("logout_method", "POST"),
        url     = config["base_url"] + logout_ep,
        headers = {"Authorization": "Bearer " + token},
    ))

    # Re-probe with the same token
    post = _probe(adapter, config, token)
    if post.is_success:
        findings.append(make_finding(
            title       = "Post-Logout Token Reuse",
            severity    = SEV_HIGH,
            description = (
                "The session token remained valid after calling the logout endpoint. "
                "An attacker who steals a token can continue using it after the victim logs out."
            ),
            evidence    = {
                "token_prefix":       token[:30] + "...",
                "post_logout_status": post.status_code,
            },
            cwe         = 613,
            remediation = (
                "Maintain a server-side session store or token denylist. "
                "Invalidate the token server-side on logout."
            ),
            phase       = "session",
            tags        = ["session", "post-logout"],
            request     = post.request,
            response    = post,
        ))

    return findings


# ── Check: session fixation ───────────────────────────────────────

def check_session_fixation(adapter, config):
    """
    Injects a known session ID into the login request via Cookie header,
    then checks if the server echoes it back or accepts it on protected endpoint.
    """
    findings = []
    FIXED_ID = "SPECTER_FIXATION_TEST_12345"

    login_url = config["base_url"] + config.get("login_endpoint", "/login")
    resp = adapter.send(BurpRequest(
        method  = "POST",
        url     = login_url,
        headers = {
            "Content-Type": "application/json",
            "Cookie":       "session={0}; sessionid={0}; PHPSESSID={0}".format(FIXED_ID),
        },
        body = config.get("login_body", ""),
    ))

    if resp.status_code >= 400:
        return findings

    # Check if the fixed ID was echoed in Set-Cookie
    sc = resp.header("Set-Cookie") or ""
    if FIXED_ID in sc:
        findings.append(make_finding(
            title       = "Session Fixation Detected",
            severity    = SEV_HIGH,
            description = (
                "Server issued the same session ID that was supplied in the login request. "
                "An attacker who plants a known session ID can hijack the session after the victim logs in."
            ),
            evidence    = {"fixed_id": FIXED_ID, "set_cookie": sc[:200]},
            cwe         = 384,
            remediation = "Always issue a new, randomly-generated session ID after successful login.",
            phase       = "session",
            tags        = ["session", "fixation"],
            request     = resp.request,
            response    = resp,
        ))

    return findings


# ── Check: no invalidation on password change ────────────────────

def check_pw_change_invalidation(adapter, config):
    """
    Opens two sessions (A = old, B = current), changes password with B,
    then checks if A is still valid.
    """
    findings = []
    pw_ep   = config.get("change_pw_endpoint", "")
    pw_body = config.get("change_pw_body", "")
    if not (pw_ep and pw_body):
        return findings

    token_a, _ = _do_login(adapter, config)
    time.sleep(0.3)
    token_b, _ = _do_login(adapter, config)

    if not token_a or not token_b:
        return findings

    # Verify both work
    if not _probe(adapter, config, token_a).is_success:
        return findings
    if not _probe(adapter, config, token_b).is_success:
        return findings

    # Change password with token B
    change_resp = adapter.send(BurpRequest(
        method  = config.get("change_pw_method", "POST"),
        url     = config["base_url"] + pw_ep,
        headers = {
            "Content-Type":  "application/json",
            "Authorization": "Bearer " + token_b,
        },
        body = pw_body,
    ))

    if change_resp.status_code >= 400:
        return findings

    # Probe old session A — should be dead
    post_a = _probe(adapter, config, token_a)
    if post_a.is_success:
        findings.append(make_finding(
            title       = "Session Not Invalidated After Password Change",
            severity    = SEV_HIGH,
            description = (
                "An existing session (token A) remained valid after the account password "
                "was changed from a different session (token B). "
                "An attacker with a stolen token retains access even after the victim resets their password."
            ),
            evidence    = {
                "token_a_prefix":   token_a[:30] + "...",
                "pw_change_status": change_resp.status_code,
                "post_change_a":    post_a.status_code,
            },
            cwe         = 613,
            remediation = "On password change, invalidate ALL existing sessions for that user.",
            phase       = "session",
            tags        = ["session", "pw-change"],
            request     = post_a.request,
            response    = post_a,
        ))

    return findings


# ── Check: response-based auth bypass ────────────────────────────

def check_response_bypass(adapter, config):
    """
    Attempts a login with wrong credentials, checks if server returns
    200 with failure keywords (prime target for response interception).
    """
    findings = []
    login_body = config.get("login_body", "")
    if not login_body:
        return findings

    # Corrupt the password field
    try:
        data = json.loads(login_body)
        for field in ("password", "pass", "passwd"):
            if field in data:
                data[field] = "SPECTER_INVALID_" + str(int(time.time()))
                break
        bad_body = json.dumps(data)
    except Exception:
        bad_body = login_body + "&password=SPECTER_INVALID"

    resp = adapter.send(BurpRequest(
        method  = "POST",
        url     = config["base_url"] + config.get("login_endpoint", "/login"),
        headers = {"Content-Type": "application/json"},
        body    = bad_body,
    ))

    if resp.status_code == 200 and resp.contains("invalid", "incorrect", "wrong", "failed", "error"):
        findings.append(make_finding(
            title       = "Potential Response-Based Auth Bypass",
            severity    = SEV_MEDIUM,
            description = (
                "Failed login returns HTTP 200 with failure text in the body. "
                "Intercepting and modifying the response body may bypass client-side auth checks."
            ),
            evidence    = {
                "status":       resp.status_code,
                "body_snippet": resp.body[:300],
            },
            cwe         = 287,
            remediation = "Return HTTP 401 on failed login. Never trust client-supplied auth state.",
            phase       = "auth",
            tags        = ["auth-bypass", "response-manipulation"],
            request     = resp.request,
            response    = resp,
        ))

    return findings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 3 — Scan runner
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SpecterScanRunner(object):
    """
    Orchestrates all checks against a target.
    Runs in a background thread so it doesn't freeze Burp's UI.

    Usage:
        runner   = SpecterScanRunner(adapter, config, on_finding, on_complete, on_status)
        thread   = threading.Thread(target=runner.run)
        thread.daemon = True
        thread.start()
    """

    def __init__(self, adapter, config, on_finding=None, on_complete=None, on_status=None):
        self.adapter     = adapter
        self.config      = config
        self.on_finding  = on_finding  or (lambda f: None)
        self.on_complete = on_complete or (lambda findings: None)
        self.on_status   = on_status   or (lambda msg: None)
        self.findings    = []
        self._stopped    = False

    def stop(self):
        """Signal the scan to stop after the current check completes."""
        self._stopped = True

    def run(self):
        """Main scan loop — calls each check in sequence."""
        try:
            self._status("Logging in to obtain valid token...")
            token, login_resp = _do_login(self.adapter, self.config)

            if token:
                self._status("Token obtained: " + token[:30] + "...")
            else:
                self._status("Login failed or token not found — limited checks only")

            checks = [
                ("JWT None-Algorithm Bypass",        self._run_none_alg,        token),
                ("JWT Algorithm Confusion",           self._run_alg_confusion,   token),
                ("Response-Based Auth Bypass",        self._run_response_bypass, None),
                ("Password Reset Token Reuse",        self._run_reset_reuse,     None),
                ("Post-Logout Token Reuse",           self._run_post_logout,     token),
                ("Session Fixation",                  self._run_fixation,        None),
                ("Session Invalidation on PW Change", self._run_pw_change,       None),
            ]

            for name, fn, arg in checks:
                if self._stopped:
                    self._status("Scan stopped by user.")
                    break
                self._status("Checking: " + name + "...")
                try:
                    if arg is not None:
                        new_findings = fn(arg)
                    else:
                        new_findings = fn()

                    for f in new_findings:
                        self.findings.append(f)
                        self.on_finding(f)

                except Exception as e:
                    err_msg = traceback.format_exc()
                    self._status("Error in {0}: {1}".format(name, str(e)))
                    self.findings.append(make_finding(
                        title       = "Check Error: " + name,
                        severity    = SEV_INFO,
                        description = str(e),
                        evidence    = {"traceback": err_msg[:500]},
                        phase       = "error",
                    ))

            self._status("Scan complete — {0} findings".format(len(self.findings)))
            self.on_complete(self.findings)

        except Exception as e:
            self._status("Fatal scan error: " + str(e))
            self.on_complete(self.findings)

    # ── Internal check wrappers ──────────────────────────────────

    def _run_none_alg(self, token):
        return check_jwt_none_alg(self.adapter, self.config, token)

    def _run_alg_confusion(self, token):
        pub_key = self.config.get("public_key_pem", "")
        return check_jwt_alg_confusion(self.adapter, self.config, token, pub_key)

    def _run_response_bypass(self):
        return check_response_bypass(self.adapter, self.config)

    def _run_reset_reuse(self):
        return check_reset_token_reuse(self.adapter, self.config)

    def _run_post_logout(self, token):
        return check_post_logout_reuse(self.adapter, self.config, token)

    def _run_fixation(self):
        return check_session_fixation(self.adapter, self.config)

    def _run_pw_change(self):
        return check_pw_change_invalidation(self.adapter, self.config)

    def _status(self, msg):
        self.on_status("[*] " + msg)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 4 — Burp UI (Swing, EDT-safe)
# Only constructed when BURP_AVAILABLE is True
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

if BURP_AVAILABLE:

    # ── Colours / fonts ─────────────────────────────────────────

    C_BG      = Color(0x0d, 0x0d, 0x11)   # near-black background
    C_SURFACE = Color(0x16, 0x16, 0x1e)   # card/panel background
    C_BORDER  = Color(0x2a, 0x2a, 0x3a)   # subtle borders
    C_TEXT    = Color(0xc9, 0xd1, 0xd9)   # primary text
    C_DIM     = Color(0x63, 0x63, 0x66)   # muted text
    C_ACCENT  = Color(0x38, 0x8b, 0xff)   # blue accent
    C_CRIT    = Color(0xe5, 0x53, 0x4b)   # critical red
    C_HIGH    = Color(0xe8, 0x97, 0x2c)   # high amber
    C_MED     = Color(0xd4, 0xb8, 0x2b)   # medium yellow
    C_LOW     = Color(0x3f, 0xb9, 0x50)   # low green
    C_INFO    = Color(0x63, 0x63, 0x66)   # info grey

    SEV_COLOR_MAP = {
        SEV_CRITICAL: C_CRIT,
        SEV_HIGH:     C_HIGH,
        SEV_MEDIUM:   C_MED,
        SEV_LOW:      C_LOW,
        SEV_INFO:     C_INFO,
    }

    FONT_MONO = Font("JetBrains Mono", Font.PLAIN, 12)
    FONT_UI   = Font("Segoe UI",       Font.PLAIN, 13)
    FONT_BOLD = Font("Segoe UI",       Font.BOLD,  13)


    def _panel(color=None, layout=None):
        """Shorthand for creating a styled JPanel."""
        p = JPanel(layout or BorderLayout())
        p.setBackground(color or C_SURFACE)
        return p


    def _label(text, color=None, font=None, align=SwingConstants.LEFT):
        lbl = JLabel(text, align)
        lbl.setForeground(color or C_TEXT)
        lbl.setFont(font or FONT_UI)
        return lbl


    def _field(text="", cols=30):
        """Styled text field."""
        f = JTextField(text, cols)
        f.setBackground(C_BG)
        f.setForeground(C_TEXT)
        f.setCaretColor(C_TEXT)
        f.setFont(FONT_MONO)
        f.setBorder(BorderFactory.createLineBorder(C_BORDER))
        return f


    def _textarea(rows=4, cols=40):
        """Styled multi-line text area."""
        ta = JTextArea(rows, cols)
        ta.setBackground(C_BG)
        ta.setForeground(C_TEXT)
        ta.setCaretColor(C_TEXT)
        ta.setFont(FONT_MONO)
        ta.setLineWrap(True)
        ta.setWrapStyleWord(True)
        ta.setBorder(BorderFactory.createLineBorder(C_BORDER))
        return ta


    def _button(text, color=None):
        """Styled JButton."""
        btn = JButton(text)
        btn.setBackground(color or C_ACCENT)
        btn.setForeground(Color.WHITE)
        btn.setFont(FONT_BOLD)
        btn.setFocusPainted(False)
        btn.setBorderPainted(False)
        btn.setCursor(java.awt.Cursor.getPredefinedCursor(java.awt.Cursor.HAND_CURSOR))
        return btn


    # ── Config panel (left side) ─────────────────────────────────

    class ScanConfigPanel(JPanel):
        """
        Left panel: form fields for target configuration.
        Fields map directly to the config dict that check functions consume.
        """

        def __init__(self):
            JPanel.__init__(self, GridBagLayout())
            self.setBackground(C_SURFACE)
            self.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12))
            self._build()

        def _build(self):
            gbc = GridBagConstraints()
            gbc.fill    = GridBagConstraints.HORIZONTAL
            gbc.insets  = Insets(4, 4, 4, 4)
            gbc.weightx = 1.0
            row = [0]  # mutable for closure

            def add_row(label_text, widget, full_width=True):
                gbc.gridy  = row[0]; row[0] += 1
                gbc.gridx  = 0; gbc.gridwidth = 1; gbc.weightx = 0
                lbl = _label(label_text, C_DIM)
                self.add(lbl, gbc)
                gbc.gridx  = 1
                gbc.gridwidth = 2 if full_width else 1
                gbc.weightx = 1.0
                self.add(widget, gbc)

            def section(title):
                gbc.gridy = row[0]; row[0] += 1
                gbc.gridx = 0; gbc.gridwidth = 3; gbc.weightx = 1.0
                panel = _panel(C_SURFACE, BorderLayout())
                lbl = _label("  " + title.upper(), C_ACCENT, FONT_BOLD)
                lbl.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER))
                panel.add(lbl, BorderLayout.CENTER)
                self.add(panel, gbc)

            # ── Target ──────────────────────────────────────────
            section("Target")
            self.fld_base_url         = _field("https://target.com")
            self.fld_protected_ep     = _field("/api/me")
            add_row("Base URL",            self.fld_base_url)
            add_row("Protected Endpoint",  self.fld_protected_ep)

            # ── Authentication ───────────────────────────────────
            section("Authentication")
            self.fld_login_ep         = _field("/login")
            self.fld_login_body       = _field('{"username":"admin","password":"admin"}', 30)
            self.fld_token_field      = _field("token")
            self.fld_logout_ep        = _field("/logout")
            add_row("Login Endpoint",      self.fld_login_ep)
            add_row("Login Body (JSON)",   self.fld_login_body)
            add_row("Token Field",         self.fld_token_field)
            add_row("Logout Endpoint",     self.fld_logout_ep)

            # ── JWT / Algorithm confusion ─────────────────────────
            section("JWT")
            self.ta_public_key        = _textarea(rows=4, cols=30)
            sp_pk = JScrollPane(self.ta_public_key)
            sp_pk.setPreferredSize(Dimension(300, 80))
            gbc.gridy = row[0]; row[0] += 1
            gbc.gridx = 0; gbc.gridwidth = 1; gbc.weightx = 0
            self.add(_label("Public Key PEM", C_DIM), gbc)
            gbc.gridx = 1; gbc.gridwidth = 2; gbc.weightx = 1.0
            self.add(sp_pk, gbc)

            # ── Password reset ────────────────────────────────────
            section("Password Reset")
            self.fld_reset_ep         = _field("/forgot-password")
            self.fld_reset_confirm_ep = _field("/reset-password")
            self.fld_reset_email      = _field("test@example.com")
            add_row("Reset Trigger EP",    self.fld_reset_ep)
            add_row("Reset Confirm EP",    self.fld_reset_confirm_ep)
            add_row("Reset Test Email",    self.fld_reset_email)

            # ── Session / password change ─────────────────────────
            section("Session")
            self.fld_change_pw_ep     = _field("/change-password")
            self.fld_change_pw_body   = _field('{"old":"admin","new":"NewP@ss1"}')
            add_row("Change PW Endpoint",  self.fld_change_pw_ep)
            add_row("Change PW Body",      self.fld_change_pw_body)

            # ── Filler to push everything up ─────────────────────
            gbc.gridy   = row[0]; row[0] += 1
            gbc.gridx   = 0; gbc.gridwidth = 3
            gbc.weighty = 1.0
            self.add(JPanel(), gbc)

        def get_config(self):
            """Collect all field values into a config dict for the scan runner."""
            return {
                "base_url":               self.fld_base_url.getText().strip(),
                "protected_endpoint":     self.fld_protected_ep.getText().strip(),
                "login_endpoint":         self.fld_login_ep.getText().strip(),
                "login_body":             self.fld_login_body.getText().strip(),
                "token_field":            self.fld_token_field.getText().strip(),
                "logout_endpoint":        self.fld_logout_ep.getText().strip(),
                "public_key_pem":         self.ta_public_key.getText().strip(),
                "reset_endpoint":         self.fld_reset_ep.getText().strip(),
                "reset_confirm_endpoint": self.fld_reset_confirm_ep.getText().strip(),
                "reset_email":            self.fld_reset_email.getText().strip(),
                "change_pw_endpoint":     self.fld_change_pw_ep.getText().strip(),
                "change_pw_body":         self.fld_change_pw_body.getText().strip(),
            }


    # ── Results panel (right side) ───────────────────────────────

    class ResultsPanel(JPanel):
        """
        Right panel: findings table + detail view.
        Findings are added row-by-row as the scan progresses.
        """

        COL_SEV   = 0
        COL_TITLE = 1
        COL_PHASE = 2
        COL_CWE   = 3

        def __init__(self):
            JPanel.__init__(self, BorderLayout())
            self.setBackground(C_BG)
            self._findings = []  # parallel list to table rows
            self._build()

        def _build(self):
            # ── Findings table ────────────────────────────────────
            self._table_model = DefaultTableModel(
                [], ["Severity", "Title", "Phase", "CWE"]
            )
            self._table = JTable(self._table_model)
            self._table.setBackground(C_SURFACE)
            self._table.setForeground(C_TEXT)
            self._table.setSelectionBackground(C_BORDER)
            self._table.setSelectionForeground(C_TEXT)
            self._table.setGridColor(C_BORDER)
            self._table.setFont(FONT_MONO)
            self._table.setRowHeight(22)
            self._table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            self._table.getTableHeader().setBackground(C_BG)
            self._table.getTableHeader().setForeground(C_DIM)
            self._table.getTableHeader().setFont(FONT_BOLD)

            # Set column widths
            cm = self._table.getColumnModel()
            cm.getColumn(0).setPreferredWidth(80)
            cm.getColumn(1).setPreferredWidth(380)
            cm.getColumn(2).setPreferredWidth(70)
            cm.getColumn(3).setPreferredWidth(60)

            # Row selection listener — updates detail view
            outer = self
            class RowSelector(MouseAdapter):
                def mouseClicked(self, evt):
                    row = outer._table.getSelectedRow()
                    if 0 <= row < len(outer._findings):
                        outer._show_detail(outer._findings[row])
            self._table.addMouseListener(RowSelector())

            scroll_table = JScrollPane(self._table)
            scroll_table.setBackground(C_BG)
            scroll_table.getViewport().setBackground(C_SURFACE)

            # ── Detail area ────────────────────────────────────────
            self._detail = _textarea(rows=20, cols=60)
            self._detail.setEditable(False)
            scroll_detail = JScrollPane(self._detail)

            # ── Status bar ────────────────────────────────────────
            self._status_lbl = _label("  Ready", C_DIM)
            self._status_lbl.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, C_BORDER))

            # ── Split pane: table top, detail bottom ──────────────
            split = JSplitPane(JSplitPane.VERTICAL_SPLIT, scroll_table, scroll_detail)
            split.setDividerLocation(280)
            split.setBackground(C_BG)

            self.add(split,            BorderLayout.CENTER)
            self.add(self._status_lbl, BorderLayout.SOUTH)

        def add_finding(self, finding):
            """Add a finding row to the table (called from scan thread via EDT)."""
            self._findings.append(finding)
            sev = finding["severity"].upper()
            cwe = str(finding["cwe"]) if finding.get("cwe") else ""
            self._table_model.addRow([sev, finding["title"], finding.get("phase", ""), cwe])

        def _show_detail(self, finding):
            """Populate the detail area with the selected finding's full info."""
            lines = []
            lines.append("=" * 60)
            lines.append("  " + finding["title"])
            lines.append("  Severity: " + finding["severity"].upper())
            lines.append("  Phase:    " + finding.get("phase", "N/A"))
            if finding.get("cwe"):
                lines.append("  CWE:      CWE-" + str(finding["cwe"]))
            lines.append("=" * 60)
            lines.append("")
            lines.append("DESCRIPTION")
            lines.append("-" * 40)
            lines.append(finding.get("description", ""))
            lines.append("")

            ev = finding.get("evidence", {})
            if ev:
                lines.append("EVIDENCE")
                lines.append("-" * 40)
                for k, v in ev.items():
                    lines.append("  {0}: {1}".format(k, v))
                lines.append("")

            rem = finding.get("remediation", "")
            if rem:
                lines.append("REMEDIATION")
                lines.append("-" * 40)
                lines.append(rem)
                lines.append("")

            tags = finding.get("tags", [])
            if tags:
                lines.append("Tags: " + ", ".join(tags))

            self._detail.setText("\n".join(lines))
            self._detail.setCaretPosition(0)

        def set_status(self, msg):
            self._status_lbl.setText("  " + msg)

        def clear(self):
            self._findings = []
            self._table_model.setRowCount(0)
            self._detail.setText("")
            self._status_lbl.setText("  Ready")


    # ── Main Specter tab ─────────────────────────────────────────

    class SpecterTab(JPanel):
        """
        The top-level tab injected into Burp's UI.
        Left: ScanConfigPanel  |  Right: ResultsPanel
        Top: toolbar (Scan / Stop / Export buttons)
        """

        def __init__(self, callbacks, helpers):
            JPanel.__init__(self, BorderLayout())
            self.setBackground(C_BG)
            self.callbacks = callbacks
            self.helpers   = helpers
            self._runner   = None
            self._thread   = None
            self._build()

        def _build(self):
            # ── Toolbar ───────────────────────────────────────────
            toolbar = _panel(C_SURFACE, BorderLayout())
            toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, C_BORDER))

            title_lbl = _label("  SPECTER", C_ACCENT, Font("Segoe UI", Font.BOLD, 15))
            sub_lbl   = _label("  Auth & Session Scanner  ", C_DIM)

            left = _panel(C_SURFACE)
            left.setLayout(BoxLayout(left, BoxLayout.X_AXIS))
            left.add(title_lbl)
            left.add(sub_lbl)

            self._btn_scan  = _button("  Run Scan  ", C_ACCENT)
            self._btn_stop  = _button("  Stop  ",     Color(0x8b, 0x14, 0x14))
            self._btn_export = _button("  Export JSON  ", C_SURFACE)
            self._btn_export.setForeground(C_TEXT)
            self._btn_stop.setEnabled(False)

            right = _panel(C_SURFACE)
            right.setLayout(BoxLayout(right, BoxLayout.X_AXIS))
            right.add(Box.createHorizontalStrut(8))
            right.add(self._btn_scan)
            right.add(Box.createHorizontalStrut(6))
            right.add(self._btn_stop)
            right.add(Box.createHorizontalStrut(6))
            right.add(self._btn_export)
            right.add(Box.createHorizontalStrut(8))

            toolbar.add(left,  BorderLayout.WEST)
            toolbar.add(right, BorderLayout.EAST)

            # ── Config + Results panels ────────────────────────────
            self._config_panel  = ScanConfigPanel()
            self._results_panel = ResultsPanel()

            config_scroll = JScrollPane(self._config_panel)
            config_scroll.setPreferredSize(Dimension(340, 600))
            config_scroll.getViewport().setBackground(C_SURFACE)

            split = JSplitPane(JSplitPane.HORIZONTAL_SPLIT, config_scroll, self._results_panel)
            split.setDividerLocation(340)
            split.setBackground(C_BG)

            self.add(toolbar, BorderLayout.NORTH)
            self.add(split,   BorderLayout.CENTER)

            # ── Wire up buttons ────────────────────────────────────
            outer = self

            class ScanAction(ActionListener):
                def actionPerformed(self, evt):
                    outer._start_scan()

            class StopAction(ActionListener):
                def actionPerformed(self, evt):
                    outer._stop_scan()

            class ExportAction(ActionListener):
                def actionPerformed(self, evt):
                    outer._export_json()

            self._btn_scan.addActionListener(ScanAction())
            self._btn_stop.addActionListener(StopAction())
            self._btn_export.addActionListener(ExportAction())

        def _start_scan(self):
            """Validate config, build adapter, start scan thread."""
            config = self._config_panel.get_config()

            if not config["base_url"]:
                JOptionPane.showMessageDialog(
                    self, "Base URL is required.", "Wraith", JOptionPane.WARNING_MESSAGE
                )
                return

            self._results_panel.clear()
            self._btn_scan.setEnabled(False)
            self._btn_stop.setEnabled(True)

            adapter = BurpHttpAdapter(self.callbacks, self.helpers)

            outer = self

            def on_finding(f):
                # Must update Swing on EDT
                class Adder(Runnable):
                    def run(self):
                        outer._results_panel.add_finding(f)
                SwingUtilities.invokeLater(Adder())

            def on_status(msg):
                class Updater(Runnable):
                    def run(self):
                        outer._results_panel.set_status(msg)
                SwingUtilities.invokeLater(Updater())

            def on_complete(findings):
                class Finisher(Runnable):
                    def run(self):
                        outer._btn_scan.setEnabled(True)
                        outer._btn_stop.setEnabled(False)
                        outer._results_panel.set_status(
                            "Complete — {0} findings".format(len(findings))
                        )
                SwingUtilities.invokeLater(Finisher())

            self._runner = SpecterScanRunner(adapter, config, on_finding, on_complete, on_status)
            self._thread = threading.Thread(target=self._runner.run)
            self._thread.daemon = True
            self._thread.start()

        def _stop_scan(self):
            if self._runner:
                self._runner.stop()
            self._btn_scan.setEnabled(True)
            self._btn_stop.setEnabled(False)

        def _export_json(self):
            """Export findings to a JSON file via file chooser dialog."""
            if not self._results_panel._findings:
                JOptionPane.showMessageDialog(self, "No findings to export.", "Wraith", JOptionPane.INFORMATION_MESSAGE)
                return

            chooser = JFileChooser()
            chooser.setSelectedFile(File("specter_findings.json"))
            result = chooser.showSaveDialog(self)

            if result == JFileChooser.APPROVE_OPTION:
                path = chooser.getSelectedFile().getAbsolutePath()
                try:
                    findings_clean = []
                    for f in self._results_panel._findings:
                        d = dict(f)
                        # Remove non-serialisable HTTP objects
                        d.pop("request",  None)
                        d.pop("response", None)
                        findings_clean.append(d)

                    with open(path, "w") as fh:
                        json.dump({
                            "scanner":       "Wraith",
                            "total_findings": len(findings_clean),
                            "findings":      findings_clean,
                        }, fh, indent=2)

                    JOptionPane.showMessageDialog(
                        self,
                        "Exported to:\n" + path,
                        "Wraith — Export Complete",
                        JOptionPane.INFORMATION_MESSAGE,
                    )
                except Exception as e:
                    JOptionPane.showMessageDialog(
                        self,
                        "Export failed: " + str(e),
                        "Wraith — Error",
                        JOptionPane.ERROR_MESSAGE,
                    )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SECTION 5 — Burp entry point
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class BurpExtender(IBurpExtender, ITab):
    """
    Burp calls registerExtenderCallbacks() on this class when the
    extension loads. This is the only entry point Burp cares about.
    """

    EXT_NAME = "Wraith"

    def registerExtenderCallbacks(self, callbacks):
        """Called once by Burp when the extension is loaded."""
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        callbacks.setExtensionName(self.EXT_NAME)

        # Build the UI on Burp's Event Dispatch Thread
        ext = self

        class UIBuilder(Runnable):
            def run(self):
                ext._tab = SpecterTab(ext._callbacks, ext._helpers)
                callbacks.addSuiteTab(ext)

        SwingUtilities.invokeLater(UIBuilder())

        callbacks.printOutput("[Wraith] Extension loaded successfully.")
        callbacks.printOutput("[Wraith] Configure target in the Specter tab and click Run Scan.")

    # ── ITab interface ───────────────────────────────────────────

    def getTabCaption(self):
        return self.EXT_NAME

    def getUiComponent(self):
        return self._tab