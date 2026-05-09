"""
tests/test_phase1.py
Specter – Phase 1 tests (no network required)
Run: python -m pytest tests/test_phase1.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
import base64
import hmac
import hashlib

from utils.token_analyzer import (
    TokenAnalyzer, TokenType, JwtAlgorithm, Severity,
    shannon_entropy, total_entropy_bits, audit_cookie_flags,
)


def _make_jwt(header: dict, payload: dict, secret: str = "", alg: str = "HS256") -> str:
    def b64e(d):
        return base64.urlsafe_b64encode(json.dumps(d, separators=(",", ":")).encode()).rstrip(b"=").decode()
    h = b64e(header)
    p = b64e(payload)
    if alg.upper() == "NONE" or not secret:
        return f"{h}.{p}."
    fn = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}[alg.upper()]
    sig = hmac.new(secret.encode(), f"{h}.{p}".encode(), fn).digest()
    return f"{h}.{p}.{base64.urlsafe_b64encode(sig).rstrip(b'=').decode()}"


analyzer = TokenAnalyzer()


# ---- JWT tests ------------------------------------------------------------

class TestJwtDetection:
    def test_detects_jwt(self):
        token = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, "secret")
        result = analyzer.analyze(token)
        assert result.token_type == TokenType.JWT

    def test_none_alg_flagged_critical(self):
        token = _make_jwt({"alg": "none", "typ": "JWT"}, {"sub": "1", "admin": True}, alg="NONE")
        result = analyzer.analyze(token)
        assert result.jwt is not None
        assert result.jwt.is_none_alg
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert any("None Algorithm" in f.title for f in critical)

    def test_weak_secret_cracked(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="secret")
        result = analyzer.analyze(token)
        assert result.jwt.cracked_secret == "secret"
        assert any("Weak Secret" in f.title for f in result.findings)

    def test_strong_secret_not_cracked(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="X9#mK!2@pQ8$nL5^wR1&zT4*vY7(uE0)")
        result = analyzer.analyze(token)
        assert result.jwt.cracked_secret is None

    def test_missing_exp_flagged(self):
        token = _make_jwt({"alg": "HS256"}, {"sub": "1"}, secret="s3cr3t")
        result = analyzer.analyze(token)
        assert any("Expiration" in f.title for f in result.findings)

    def test_rs256_confusion_hint(self):
        token = _make_jwt({"alg": "RS256"}, {"sub": "1", "exp": 9999999999})
        result = analyzer.analyze(token)
        assert any("Confusion" in f.title for f in result.findings)

    def test_forge_none_alg(self):
        original = _make_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1", "admin": False}, "secret")
        forged = analyzer.forge_none_alg(original)
        assert forged is not None
        assert forged.endswith(".")
        h, p, s = forged.split(".")
        assert s == ""
        header = json.loads(base64.urlsafe_b64decode(h + "=="))
        assert header["alg"] == "none"

    def test_kid_injection_detected(self):
        token = _make_jwt({"alg": "HS256", "kid": "../../etc/passwd"}, {"sub": "1"})
        result = analyzer.analyze(token)
        assert any("kid" in f.title.lower() for f in result.findings)

    def test_jku_header_flagged(self):
        token = _make_jwt({"alg": "RS256", "jku": "https://evil.com/jwks.json"}, {"sub": "1", "exp": 9999999999})
        result = analyzer.analyze(token)
        assert any("jku" in f.title.lower() or "x5u" in f.title.lower() for f in result.findings)


# ---- Entropy tests --------------------------------------------------------

class TestEntropy:
    def test_high_entropy_opaque(self):
        token = "a3f8c2d91e047b56af12e8cd490b37fe"  # hex session token
        result = analyzer.analyze(token, context="session_cookie")
        # Should not flag entropy for a proper hex token
        entropy_findings = [f for f in result.findings if "Entropy" in f.title]
        assert len(entropy_findings) == 0

    def test_low_entropy_flagged(self):
        token = "aaaaaaaaaaaaaaaaaaaaaaaa"
        result = analyzer.analyze(token, context="session_cookie")
        assert any("Entropy" in f.title for f in result.findings)

    def test_short_token_flagged(self):
        token = "abc123"
        result = analyzer.analyze(token)
        assert any("Short" in f.title for f in result.findings)

    def test_numeric_token_flagged(self):
        token = "123456789"
        result = analyzer.analyze(token)
        assert any("Numeric" in f.title or "Sequential" in f.title for f in result.findings)

    def test_batch_common_prefix_detected(self):
        tokens = [f"FIXED_PREFIX_{i:08x}" for i in range(5)]
        analyses = analyzer.analyze_batch(tokens)
        all_findings = [f for a in analyses for f in a.findings]
        assert any("Prefix" in f.title for f in all_findings)


# ---- Cookie tests ---------------------------------------------------------

class TestCookieFlags:
    def test_secure_httponly_samesite_clean(self):
        audit = audit_cookie_flags("session=abc123; HttpOnly; Secure; SameSite=Strict; Path=/")
        assert len(audit.findings) == 0

    def test_missing_httponly(self):
        audit = audit_cookie_flags("session=abc123; Secure; SameSite=Strict")
        assert any("HttpOnly" in f.title for f in audit.findings)
        assert any(f.severity == Severity.HIGH for f in audit.findings)

    def test_missing_secure(self):
        audit = audit_cookie_flags("session=abc123; HttpOnly; SameSite=Lax")
        assert any("Secure" in f.title for f in audit.findings)

    def test_missing_samesite(self):
        audit = audit_cookie_flags("session=abc123; HttpOnly; Secure")
        assert any("SameSite" in f.title for f in audit.findings)

    def test_samesite_none_without_secure(self):
        audit = audit_cookie_flags("session=abc123; SameSite=None")
        titles = [f.title for f in audit.findings]
        assert any("SameSite=None" in t for t in titles)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])