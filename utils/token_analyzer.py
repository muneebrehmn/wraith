"""
utils/token_analyzer.py
Wraith – Token Analysis Engine
Covers: JWT (none-alg, alg-confusion, timing), opaque token entropy, session cookie flags
"""

from __future__ import annotations

import re
import math
import json
import time
import hmac
import base64
import hashlib
import statistics
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


# ---------------------------------------------------------------------------
# Enums + constants
# ---------------------------------------------------------------------------

class TokenType(Enum):
    JWT         = "jwt"
    OPAQUE      = "opaque"        # hex / alphanumeric session token
    BASE64      = "base64"        # encoded but not JWT
    NUMERIC     = "numeric"       # sequential ID masquerading as token
    UNKNOWN     = "unknown"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class JwtAlgorithm(Enum):
    HS256 = "HS256"; HS384 = "HS384"; HS512 = "HS512"
    RS256 = "RS256"; RS384 = "RS384"; RS512 = "RS512"
    ES256 = "ES256"; ES384 = "ES384"; ES512 = "ES512"
    PS256 = "PS256"; PS384 = "PS384"; PS512 = "PS512"
    NONE  = "none"
    UNKNOWN = "unknown"


WEAK_SECRETS = [
    "secret", "password", "123456", "key", "jwt", "token",
    "changeme", "admin", "test", "supersecret", "qwerty",
    "letmein", "welcome", "monkey", "dragon", "",
]

# Minimum Shannon entropy thresholds (bits/char)
ENTROPY_THRESHOLDS = {
    "session_cookie":  3.5,
    "csrf_token":      3.5,
    "api_key":         4.0,
    "password_reset":  4.5,
}


# ---------------------------------------------------------------------------
# Core result types
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    title:       str
    severity:    Severity
    description: str
    evidence:    Dict[str, Any]  = field(default_factory=dict)
    cwe:         Optional[int]   = None
    remediation: str             = ""


@dataclass
class JwtAnalysis:
    raw:           str
    header:        Dict[str, Any]
    payload:       Dict[str, Any]
    signature:     bytes
    algorithm:     JwtAlgorithm
    findings:      List[Finding]  = field(default_factory=list)
    cracked_secret: Optional[str] = None

    @property
    def is_none_alg(self) -> bool:
        return self.algorithm == JwtAlgorithm.NONE

    @property
    def is_symmetric(self) -> bool:
        return self.algorithm in (
            JwtAlgorithm.HS256, JwtAlgorithm.HS384, JwtAlgorithm.HS512
        )

    @property
    def is_asymmetric(self) -> bool:
        return self.algorithm in (
            JwtAlgorithm.RS256, JwtAlgorithm.RS384, JwtAlgorithm.RS512,
            JwtAlgorithm.ES256, JwtAlgorithm.ES384, JwtAlgorithm.ES512,
            JwtAlgorithm.PS256, JwtAlgorithm.PS384, JwtAlgorithm.PS512,
        )


@dataclass
class TokenAnalysis:
    raw:           str
    token_type:    TokenType
    entropy_bits:  float
    char_entropy:  float          # bits per character (Shannon)
    length:        int
    findings:      List[Finding]  = field(default_factory=list)
    jwt:           Optional[JwtAnalysis] = None
    metadata:      Dict[str, Any] = field(default_factory=dict)

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def highest_severity(self) -> Optional[Severity]:
        if not self.findings:
            return None
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
                 Severity.LOW, Severity.INFO]
        for sev in order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return None

    def findings_by_severity(self, sev: Severity) -> List[Finding]:
        return [f for f in self.findings if f.severity == sev]


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decode with padding tolerance."""
    data = data.replace("-", "+").replace("_", "/")
    pad = 4 - len(data) % 4
    if pad != 4:
        data += "=" * pad
    return base64.b64decode(data)


def _b64_encode_unpadded(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _parse_jwt_raw(token: str) -> Tuple[Dict, Dict, bytes, str, str]:
    """Returns (header_dict, payload_dict, sig_bytes, header_b64, payload_b64)."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError(f"JWT must have 3 parts, got {len(parts)}")

    header_b64, payload_b64, sig_b64 = parts

    header  = json.loads(_b64_decode(header_b64))
    payload = json.loads(_b64_decode(payload_b64))
    sig     = _b64_decode(sig_b64)

    return header, payload, sig, header_b64, payload_b64


def _hmac_verify(header_b64: str, payload_b64: str, sig: bytes, secret: str, alg: str) -> bool:
    msg     = f"{header_b64}.{payload_b64}".encode()
    hash_fn = {
        "HS256": hashlib.sha256,
        "HS384": hashlib.sha384,
        "HS512": hashlib.sha512,
    }.get(alg.upper())
    if not hash_fn:
        return False
    expected = hmac.new(secret.encode(), msg, hash_fn).digest()
    return hmac.compare_digest(expected, sig)


# ---------------------------------------------------------------------------
# Entropy
# ---------------------------------------------------------------------------

def shannon_entropy(data: str) -> float:
    """Shannon entropy in bits per character."""
    if not data:
        return 0.0
    freq = {}
    for c in data:
        freq[c] = freq.get(c, 0) + 1
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def total_entropy_bits(data: str) -> float:
    """Total entropy: H(X) * length."""
    return shannon_entropy(data) * len(data)


# ---------------------------------------------------------------------------
# Main analyzer
# ---------------------------------------------------------------------------

class TokenAnalyzer:
    """
    Stateless token analysis engine.
    All analysis methods return TokenAnalysis or JwtAnalysis objects.
    Thread-safe (no mutable state).
    """

    # ---- public entry points -----------------------------------------------

    def analyze(self, token: str, context: str = "generic") -> TokenAnalysis:
        """
        Universal entry point. Detects token type and dispatches to
        the correct sub-analyzer.
        """
        token = token.strip()
        ttype = self._detect_type(token)

        char_ent  = shannon_entropy(token)
        total_ent = total_entropy_bits(token)

        result = TokenAnalysis(
            raw          = token,
            token_type   = ttype,
            entropy_bits = total_ent,
            char_entropy = char_ent,
            length       = len(token),
            metadata     = {"context": context},
        )

        if ttype == TokenType.JWT:
            try:
                result.jwt = self._analyze_jwt(token)
                result.findings.extend(result.jwt.findings)
            except Exception as e:
                result.findings.append(Finding(
                    title       = "JWT Parse Error",
                    severity    = Severity.INFO,
                    description = str(e),
                    evidence    = {"raw_snippet": token[:60]},
                ))
        else:
            result.findings.extend(self._analyze_opaque(token, context))

        return result

    def analyze_batch(
        self, tokens: List[str], context: str = "session"
    ) -> List[TokenAnalysis]:
        """
        Analyze a batch of tokens (e.g., sequential session IDs).
        Also performs cross-token predictability analysis.
        """
        analyses = [self.analyze(t, context) for t in tokens]
        cross_findings = self._cross_token_analysis(tokens, analyses)
        for a in analyses:
            a.findings.extend(cross_findings)
        return analyses

    def forge_none_alg(self, jwt_token: str) -> Optional[str]:
        """
        Produces a none-algorithm variant of a JWT for testing.
        Returns forged token or None if parsing fails.
        """
        try:
            header, payload, _, _, _ = _parse_jwt_raw(jwt_token)
        except ValueError:
            return None

        header["alg"] = "none"
        new_header  = _b64_encode_unpadded(json.dumps(header, separators=(",", ":")).encode())
        new_payload = _b64_encode_unpadded(json.dumps(payload, separators=(",", ":")).encode())
        return f"{new_header}.{new_payload}."

    def forge_alg_confusion(self, jwt_token: str, public_key_pem: str) -> Optional[str]:
        """
        RS256 → HS256 algorithm confusion attack.
        Signs the token with the public key as the HMAC secret.
        Returns forged token or None on failure.
        """
        try:
            header, payload, _, _, _ = _parse_jwt_raw(jwt_token)
        except ValueError:
            return None

        header["alg"] = "HS256"
        new_header  = _b64_encode_unpadded(json.dumps(header, separators=(",", ":")).encode())
        new_payload = _b64_encode_unpadded(json.dumps(payload, separators=(",", ":")).encode())

        msg = f"{new_header}.{new_payload}".encode()
        sig = hmac.new(public_key_pem.encode(), msg, hashlib.sha256).digest()
        return f"{new_header}.{new_payload}.{_b64_encode_unpadded(sig)}"

    def crack_weak_secret(self, jwt_token: str, wordlist: Optional[List[str]] = None) -> Optional[str]:
        """
        Attempts HMAC secret cracking against a wordlist.
        Falls back to WEAK_SECRETS if no wordlist provided.
        """
        wl = wordlist or WEAK_SECRETS
        try:
            header, _, sig, header_b64, payload_b64 = _parse_jwt_raw(jwt_token)
        except ValueError:
            return None

        alg = header.get("alg", "").upper()
        if alg not in ("HS256", "HS384", "HS512"):
            return None

        for secret in wl:
            if _hmac_verify(header_b64, payload_b64, sig, secret, alg):
                return secret
        return None

    # ---- type detection ----------------------------------------------------

    def _detect_type(self, token: str) -> TokenType:
        # JWT: three base64url segments separated by dots
        parts = token.split(".")
        if len(parts) == 3:
            try:
                hdr = json.loads(_b64_decode(parts[0]))
                if "alg" in hdr or "typ" in hdr:
                    return TokenType.JWT
            except Exception:
                pass

        # Pure numeric — likely sequential ID
        if token.isdigit():
            return TokenType.NUMERIC

        # Hex string (typical session token)
        if re.fullmatch(r"[0-9a-fA-F]+", token):
            return TokenType.OPAQUE

        # Base64-ish but not JWT
        if re.fullmatch(r"[A-Za-z0-9+/=_-]+", token) and len(token) > 8:
            try:
                _b64_decode(token)
                return TokenType.BASE64
            except Exception:
                pass

        return TokenType.UNKNOWN

    # ---- JWT analysis ------------------------------------------------------

    def _analyze_jwt(self, token: str) -> JwtAnalysis:
        header, payload, sig, header_b64, payload_b64 = _parse_jwt_raw(token)

        alg_str = header.get("alg", "unknown").upper()
        try:
            alg = JwtAlgorithm[alg_str]
        except KeyError:
            alg = JwtAlgorithm.UNKNOWN

        analysis = JwtAnalysis(
            raw       = token,
            header    = header,
            payload   = payload,
            signature = sig,
            algorithm = alg,
        )

        # --- none algorithm -------------------------------------------------
        if alg == JwtAlgorithm.NONE:
            analysis.findings.append(Finding(
                title       = "JWT None Algorithm Accepted",
                severity    = Severity.CRITICAL,
                description = (
                    "Token specifies alg=none, meaning the signature is not verified. "
                    "An attacker can forge arbitrary claims."
                ),
                evidence    = {"header": header, "payload": payload},
                cwe         = 347,
                remediation = "Reject tokens with alg=none. Enforce a specific allowed algorithm server-side.",
            ))

        # --- weak HMAC secret -----------------------------------------------
        if alg in (JwtAlgorithm.HS256, JwtAlgorithm.HS384, JwtAlgorithm.HS512):
            cracked = self.crack_weak_secret(token)
            if cracked is not None:
                analysis.cracked_secret = cracked
                analysis.findings.append(Finding(
                    title       = "JWT Signed With Weak Secret",
                    severity    = Severity.CRITICAL,
                    description = f"HMAC secret cracked from wordlist: '{cracked}'",
                    evidence    = {"algorithm": alg_str, "secret": cracked},
                    cwe         = 326,
                    remediation = "Use a cryptographically random secret of at least 256 bits.",
                ))

        # --- algorithm confusion hint ---------------------------------------
        if alg in (JwtAlgorithm.RS256, JwtAlgorithm.RS384, JwtAlgorithm.RS512):
            analysis.findings.append(Finding(
                title       = "RS→HS Algorithm Confusion Candidate",
                severity    = Severity.HIGH,
                description = (
                    f"Token uses {alg_str}. If the server accepts HS256 and uses the "
                    "public key as the HMAC secret, an alg-confusion attack is possible."
                ),
                evidence    = {"algorithm": alg_str},
                cwe         = 347,
                remediation = "Enforce a strict algorithm allowlist server-side. Never accept HS* if using RS*.",
            ))

        # --- critical claims ------------------------------------------------
        self._check_jwt_claims(payload, analysis.findings)

        # --- kid / jku header injection ------------------------------------
        self._check_jwt_header_injection(header, analysis.findings)

        return analysis

    def _check_jwt_claims(self, payload: Dict, findings: List[Finding]):
        import time as _time

        # Missing expiry
        if "exp" not in payload:
            findings.append(Finding(
                title       = "JWT Missing Expiration (exp)",
                severity    = Severity.MEDIUM,
                description = "Token has no expiry. Stolen tokens remain valid indefinitely.",
                evidence    = {"payload_keys": list(payload.keys())},
                cwe         = 613,
                remediation = "Always set a short exp claim (≤15 min for sensitive flows).",
            ))
        else:
            exp = payload["exp"]
            now = _time.time()
            if exp < now:
                findings.append(Finding(
                    title       = "JWT Already Expired",
                    severity    = Severity.INFO,
                    description = "Token exp claim is in the past.",
                    evidence    = {"exp": exp, "now": now, "delta_s": now - exp},
                ))
            elif exp - now > 86400 * 30:
                findings.append(Finding(
                    title       = "JWT Has Excessively Long Lifetime",
                    severity    = Severity.LOW,
                    description = f"Token expires in {(exp - now) / 86400:.1f} days.",
                    evidence    = {"exp": exp},
                    cwe         = 613,
                    remediation = "Reduce token lifetime. Use refresh tokens for long-lived sessions.",
                ))

        # Privilege escalation-relevant claims
        for claim in ("role", "admin", "is_admin", "scope", "permissions", "groups"):
            if claim in payload:
                findings.append(Finding(
                    title       = f"JWT Contains Sensitive Claim: {claim}",
                    severity    = Severity.INFO,
                    description = (
                        f"Payload includes '{claim}'. "
                        "Verify this claim is validated server-side and not client-trusted."
                    ),
                    evidence    = {claim: payload[claim]},
                    cwe         = 269,
                    remediation = "Never trust client-side role/scope claims without server-side validation.",
                ))

    def _check_jwt_header_injection(self, header: Dict, findings: List[Finding]):
        if "kid" in header:
            kid_val = str(header["kid"])
            # SQL injection probe in kid
            if any(c in kid_val for c in ("'", '"', "--", ";", "/")):
                findings.append(Finding(
                    title       = "JWT kid Header Injection Risk",
                    severity    = Severity.HIGH,
                    description = "kid value contains special characters; potential SQL/path injection.",
                    evidence    = {"kid": kid_val},
                    cwe         = 89,
                    remediation = "Treat kid as an opaque identifier. Validate against an allowlist.",
                ))

        if "jku" in header or "x5u" in header:
            url_val = header.get("jku") or header.get("x5u")
            findings.append(Finding(
                title       = "JWT jku/x5u Header Present",
                severity    = Severity.HIGH,
                description = (
                    f"jku/x5u present ({url_val}). "
                    "Server may fetch a malicious JWKS URI supplied by attacker."
                ),
                evidence    = {"url": url_val},
                cwe         = 918,
                remediation = "Never follow jku/x5u URLs from untrusted tokens. Pin JWKS URI server-side.",
            ))

    # ---- opaque token analysis ---------------------------------------------

    def _analyze_opaque(self, token: str, context: str) -> List[Finding]:
        findings: List[Finding] = []
        ent_per_char = shannon_entropy(token)
        total_ent    = total_entropy_bits(token)
        threshold    = ENTROPY_THRESHOLDS.get(context, 3.5)

        if ent_per_char < threshold:
            findings.append(Finding(
                title       = "Low-Entropy Token",
                severity    = Severity.HIGH,
                description = (
                    f"Token entropy {ent_per_char:.2f} bits/char is below the "
                    f"{threshold} threshold for '{context}' tokens."
                ),
                evidence    = {
                    "entropy_per_char": round(ent_per_char, 3),
                    "total_bits":       round(total_ent, 1),
                    "token_length":     len(token),
                    "context":          context,
                },
                cwe         = 330,
                remediation = "Use secrets.token_hex(32) or equivalent CSPRNG with ≥128 bits of entropy.",
            ))

        if len(token) < 16:
            findings.append(Finding(
                title       = "Short Token (Brute-Force Risk)",
                severity    = Severity.MEDIUM,
                description = f"Token length {len(token)} chars is unusually short.",
                evidence    = {"length": len(token)},
                cwe         = 330,
                remediation = "Minimum 128-bit (16 raw bytes / 32 hex chars) for session tokens.",
            ))

        if token.isdigit():
            findings.append(Finding(
                title       = "Numeric / Sequential Token",
                severity    = Severity.HIGH,
                description = "Token appears to be a plain integer — likely guessable or IDOR-vulnerable.",
                evidence    = {"token": token},
                cwe         = 330,
                remediation = "Replace integer IDs with opaque random tokens in externally-facing parameters.",
            ))

        return findings

    # ---- cross-token analysis ----------------------------------------------

    def _cross_token_analysis(
        self, tokens: List[str], analyses: List[TokenAnalysis]
    ) -> List[Finding]:
        findings: List[Finding] = []
        if len(tokens) < 2:
            return findings

        # Entropy variance
        entropies = [a.char_entropy for a in analyses]
        try:
            variance = statistics.variance(entropies)
            if variance < 0.05:
                findings.append(Finding(
                    title       = "Low Entropy Variance Across Token Set",
                    severity    = Severity.HIGH,
                    description = (
                        f"Entropy variance across {len(tokens)} tokens is {variance:.4f}. "
                        "Tokens may be generated from a weak PRNG with predictable output."
                    ),
                    evidence    = {
                        "variance":  round(variance, 5),
                        "entropies": [round(e, 3) for e in entropies],
                    },
                    cwe         = 335,
                    remediation = "Use OS-level CSPRNG (secrets module, /dev/urandom).",
                ))
        except statistics.StatisticsError:
            pass

        # Common prefix detection (opaque + unknown — catches mixed-charset tokens)
        if all(a.token_type in (TokenType.OPAQUE, TokenType.UNKNOWN) for a in analyses):
            prefix_len = self._common_prefix_length(tokens)
            if prefix_len >= 4:
                findings.append(Finding(
                    title       = "Common Prefix in Token Set",
                    severity    = Severity.MEDIUM,
                    description = (
                        f"All {len(tokens)} tokens share a {prefix_len}-char prefix. "
                        "Suggests a static seed or timestamp component."
                    ),
                    evidence    = {"common_prefix": tokens[0][:prefix_len]},
                    cwe         = 335,
                ))

        return findings

    @staticmethod
    def _common_prefix_length(tokens: List[str]) -> int:
        if not tokens:
            return 0
        ref = tokens[0]
        for i, c in enumerate(ref):
            if not all(len(t) > i and t[i] == c for t in tokens[1:]):
                return i
        return len(ref)


# ---------------------------------------------------------------------------
# Cookie-flag auditor (standalone helper)
# ---------------------------------------------------------------------------

@dataclass
class CookieAudit:
    name:          str
    value:         str
    flags:         Dict[str, Any]
    findings:      List[Finding] = field(default_factory=list)


def audit_cookie_flags(set_cookie_header: str) -> CookieAudit:
    """
    Parses a Set-Cookie header and checks security flags.
    """
    parts  = [p.strip() for p in set_cookie_header.split(";")]
    name_val = parts[0].split("=", 1) if "=" in parts[0] else [parts[0], ""]
    name, value = name_val[0].strip(), (name_val[1].strip() if len(name_val) > 1 else "")

    flags: Dict[str, Any] = {}
    for part in parts[1:]:
        if "=" in part:
            k, v = part.split("=", 1)
            flags[k.strip().lower()] = v.strip()
        else:
            flags[part.lower()] = True

    findings: List[Finding] = []

    if "httponly" not in flags:
        findings.append(Finding(
            title       = "Cookie Missing HttpOnly Flag",
            severity    = Severity.HIGH,
            description = f"Cookie '{name}' is accessible via JavaScript — XSS can steal it.",
            evidence    = {"cookie": name},
            cwe         = 1004,
            remediation = "Set HttpOnly on all session and auth cookies.",
        ))

    if "secure" not in flags:
        findings.append(Finding(
            title       = "Cookie Missing Secure Flag",
            severity    = Severity.MEDIUM,
            description = f"Cookie '{name}' can be transmitted over HTTP.",
            evidence    = {"cookie": name},
            cwe         = 614,
            remediation = "Set Secure on all cookies carrying sensitive data.",
        ))

    samesite = flags.get("samesite", "").lower()
    if not samesite:
        findings.append(Finding(
            title       = "Cookie Missing SameSite Attribute",
            severity    = Severity.MEDIUM,
            description = f"Cookie '{name}' has no SameSite attribute — CSRF risk.",
            evidence    = {"cookie": name},
            cwe         = 352,
            remediation = "Set SameSite=Strict or SameSite=Lax.",
        ))
    elif samesite == "none" and "secure" not in flags:
        findings.append(Finding(
            title       = "SameSite=None Without Secure",
            severity    = Severity.HIGH,
            description = f"Cookie '{name}' is SameSite=None but not Secure.",
            evidence    = {"cookie": name},
            cwe         = 614,
        ))

    return CookieAudit(name=name, value=value, flags=flags, findings=findings)