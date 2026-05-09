"""
wraith/tests/test_phase5.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 5 tests — Reporter
Run: python -m pytest tests/test_phase5.py -v
"""

import sys, os, json, tempfile
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.reporter import Reporter
from models.findings import ScanFinding, Severity, Category


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Sample finding factory
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def make_finding(
    title    = "Test Finding",
    severity = Severity.HIGH,
    category = Category.AUTH,
    phase    = "auth",
    cwe      = 347,
    tags     = None,
    evidence = None,
    remediation = "Fix it.",
    description = "Something is wrong.",
) -> ScanFinding:
    return ScanFinding(
        title       = title,
        severity    = severity,
        category    = category,
        phase       = phase,
        cwe         = cwe,
        tags        = tags or ["test"],
        evidence    = evidence or {"key": "value"},
        remediation = remediation,
        description = description,
    )


def sample_findings():
    """A realistic cross-phase finding set for report generation tests."""
    return [
        make_finding("JWT None-Algorithm Bypass",        Severity.CRITICAL, Category.AUTH,           "auth",    347, ["jwt","none-alg"]),
        make_finding("JWT Signed With Weak Secret",      Severity.CRITICAL, Category.AUTH,           "auth",    326, ["jwt","weak-secret"]),
        make_finding("Price Tampering: Negative Price",  Severity.CRITICAL, Category.BUSINESS_LOGIC, "logic",   840, ["price-tampering"]),
        make_finding("Post-Logout Token Reuse",          Severity.HIGH,     Category.SESSION,         "session", 613, ["post-logout"]),
        make_finding("Role Parameter Injection",         Severity.HIGH,     Category.AUTH,            "auth",    269, ["role-injection"]),
        make_finding("Coupon Stacking Accepted",         Severity.HIGH,     Category.BUSINESS_LOGIC,  "logic",   840, ["coupon"]),
        make_finding("Cookie Missing HttpOnly",          Severity.HIGH,     Category.SESSION,          "session", 1004,["cookie"]),
        make_finding("No Concurrent Session Limit",      Severity.MEDIUM,   Category.SESSION,          "session", 613, ["concurrent"]),
        make_finding("JWT Has Long Lifetime",            Severity.LOW,      Category.TOKEN,            "auth",    613, ["jwt"]),
        make_finding("Race Condition Recommend Test",    Severity.INFO,     Category.BUSINESS_LOGIC,   "logic",   None,["coupon","race"]),
    ]


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# JSON tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestJsonReport:

    def _reporter(self, findings=None, tmpdir=None):
        return Reporter(
            findings    = findings if findings is not None else sample_findings(),
            target_url  = "https://target.example.com",
            scan_name   = "Wraith Test Scan",
            output_dir  = tmpdir or tempfile.mkdtemp(),
        )

    def test_json_file_created(self):
        tmpdir = tempfile.mkdtemp()
        r = self._reporter(tmpdir=tmpdir)
        path = r.write_json()
        assert os.path.exists(path)

    def test_json_valid_structure(self):
        """JSON must have meta, summary, findings keys."""
        tmpdir = tempfile.mkdtemp()
        r      = self._reporter(tmpdir=tmpdir)
        path   = r.write_json()
        with open(path) as f:
            data = json.load(f)
        assert "meta"     in data
        assert "summary"  in data
        assert "findings" in data

    def test_json_finding_count_matches(self):
        findings = sample_findings()
        tmpdir   = tempfile.mkdtemp()
        r = Reporter(findings=findings, output_dir=tmpdir)
        path = r.write_json()
        with open(path) as f:
            data = json.load(f)
        assert data["meta"]["total_findings"] == len(findings)
        assert len(data["findings"])          == len(findings)

    def test_json_severity_counts_correct(self):
        findings = sample_findings()
        tmpdir   = tempfile.mkdtemp()
        r = Reporter(findings=findings, output_dir=tmpdir)
        path = r.write_json()
        with open(path) as f:
            data = json.load(f)
        counts = data["summary"]["by_severity"]
        assert counts["critical"] == 3
        assert counts["high"]     == 4
        assert counts["medium"]   == 1
        assert counts["low"]      == 1
        assert counts["info"]     == 1

    def test_json_findings_sorted_by_severity(self):
        """Critical findings must appear before high, high before medium, etc."""
        findings = sample_findings()
        tmpdir   = tempfile.mkdtemp()
        r = Reporter(findings=findings, output_dir=tmpdir)
        path = r.write_json()
        with open(path) as f:
            data = json.load(f)
        sev_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        scores = [sev_order[f["severity"]] for f in data["findings"]]
        assert scores == sorted(scores, reverse=True)

    def test_json_cwe_url_present(self):
        findings = [make_finding(cwe=347)]
        tmpdir   = tempfile.mkdtemp()
        r = Reporter(findings=findings, output_dir=tmpdir)
        path = r.write_json()
        with open(path) as f:
            data = json.load(f)
        assert "cwe_url" in data["findings"][0]
        assert "347" in data["findings"][0]["cwe_url"]

    def test_json_empty_findings(self):
        """Empty findings list → valid JSON with zero counts."""
        tmpdir = tempfile.mkdtemp()
        r = Reporter(findings=[], output_dir=tmpdir)
        path = r.write_json()
        with open(path) as f:
            data = json.load(f)
        assert data["meta"]["total_findings"] == 0
        assert data["findings"] == []

    def test_json_risk_score(self):
        """Risk score = sum of severity scores (critical=5, high=4 ...)."""
        findings = [
            make_finding(severity=Severity.CRITICAL),
            make_finding(severity=Severity.HIGH),
        ]
        tmpdir = tempfile.mkdtemp()
        r = Reporter(findings=findings, output_dir=tmpdir)
        path = r.write_json()
        with open(path) as f:
            data = json.load(f)
        assert data["summary"]["risk_score"] == 9   # 5 + 4


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HTML tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestHtmlReport:

    def _gen(self, findings=None):
        tmpdir = tempfile.mkdtemp()
        r = Reporter(
            findings   = findings if findings is not None else sample_findings(),
            target_url = "https://target.example.com",
            scan_name  = "Wraith HTML Test",
            output_dir = tmpdir,
        )
        path = r.write_html()
        return open(path).read()

    def test_html_file_created(self):
        tmpdir = tempfile.mkdtemp()
        r = Reporter(findings=sample_findings(), output_dir=tmpdir)
        path = r.write_html()
        assert os.path.exists(path)
        assert path.endswith(".html")

    def test_html_is_valid_skeleton(self):
        html = self._gen()
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<body" in html
        assert "</body>" in html

    def test_html_contains_finding_titles(self):
        html = self._gen()
        assert "JWT None-Algorithm Bypass" in html
        assert "Post-Logout Token Reuse"   in html
        assert "Coupon Stacking Accepted"  in html

    def test_html_contains_severity_badges(self):
        html = self._gen()
        assert "CRITICAL" in html
        assert "HIGH"     in html
        assert "MEDIUM"   in html

    def test_html_contains_cwe_links(self):
        html = self._gen()
        assert "cwe.mitre.org" in html
        assert "CWE-347"       in html

    def test_html_contains_filter_js(self):
        """JS filter functions must be present."""
        html = self._gen()
        assert "filterBySev"   in html
        assert "filterByPhase" in html
        assert "toggleCard"    in html

    def test_html_escapes_special_chars(self):
        """XSS-prone content in finding fields must be escaped."""
        evil_finding = make_finding(
            title       = '<script>alert("xss")</script>',
            description = "<b>bold</b> & 'quotes'",
        )
        html = self._gen(findings=[evil_finding])
        # Raw tags must not appear — only escaped forms
        assert "<script>alert" not in html
        assert "&lt;script&gt;" in html
        assert "&amp;" in html

    def test_html_empty_findings_shows_empty_state(self):
        html = self._gen(findings=[])
        assert "No findings" in html or "scan clean" in html.lower()

    def test_html_contains_target_url(self):
        html = self._gen()
        assert "target.example.com" in html

    def test_html_self_contained_no_external(self):
        """Report must not reference external scripts or stylesheets."""
        html = self._gen()
        # Should not load external resources
        for bad in ["cdn.jsdelivr", "cdnjs.cloudflare", "unpkg.com", "googleapis.com/css"]:
            assert bad not in html, f"Found external resource: {bad}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Summary text tests
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestSummaryText:

    def test_summary_contains_counts(self):
        r    = Reporter(findings=sample_findings(), output_dir=tempfile.mkdtemp())
        text = r.summary_text()
        assert "CRITICAL" in text
        assert "HIGH"     in text
        assert "(3)"      in text   # 3 critical findings

    def test_summary_empty(self):
        r    = Reporter(findings=[], output_dir=tempfile.mkdtemp())
        text = r.summary_text()
        assert "0 findings" in text

    def test_summary_risk_score(self):
        findings = [make_finding(severity=Severity.CRITICAL)] * 2
        r    = Reporter(findings=findings, output_dir=tempfile.mkdtemp())
        text = r.summary_text()
        assert "10" in text   # 2 × 5


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Smoke test: generate a real sample report to outputs/ for visual inspection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def generate_sample_report(out_dir: str = "./reports"):
    """
    Generates a sample JSON + HTML report with realistic findings.
    Call directly to inspect the HTML output in a browser:
        python tests/test_phase5.py
    """
    from utils.http_client import HttpRequest, HttpResponse

    # Attach fake request/response objects to some findings for full rendering
    fake_req = HttpRequest(
        method  = "GET",
        url     = "https://target.example.com/api/me",
        headers = {"Authorization": "Bearer eyJhbGci..."},
    )
    fake_resp = HttpResponse(
        status_code = 200,
        headers     = {"content-type": "application/json", "x-user-id": "1"},
        body        = '{"id": 1, "role": "admin", "email": "admin@target.com"}',
        elapsed_ms  = 82.4,
        request     = fake_req,
    )

    findings = sample_findings()

    # Attach HTTP context to the first two findings
    findings[0].request  = fake_req
    findings[0].response = fake_resp
    findings[1].request  = fake_req

    r = Reporter(
        findings        = findings,
        target_url      = "https://target.example.com",
        scan_name       = "Wraith — Sample Engagement Report",
        output_dir      = out_dir,
        scanner_version = "1.0.0",
    )

    json_path = r.write_json()
    html_path = r.write_html()
    print(r.summary_text())
    print(f"\nOpen in browser: file://{os.path.abspath(html_path)}")
    return json_path, html_path


if __name__ == "__main__":
    generate_sample_report("./reports")