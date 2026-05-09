"""
wraith/core/engine.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Wraith – Scan Orchestrator + CLI Entry Point

Ties together all scanner phases into a single cohesive scan run:
  Phase 2 → AuthTester      (JWT attacks, password reset abuse)
  Phase 3 → LogicTester     (price tampering, role injection, workflow skipping)
  Phase 4 → SessionAnalyzer (post-logout reuse, fixation, concurrent sessions)
  Phase 5 → Reporter        (JSON + HTML output)

Usage (CLI):
    python -m core.engine --target https://api.target.com \\
        --login-endpoint /api/login \\
        --login-body '{"username":"admin","password":"admin"}' \\
        --login-token-field token \\
        --protected-endpoint /api/me \\
        --output-dir ./reports \\
        --proxy                    # route through Burp on 127.0.0.1:8080

Usage (programmatic):
    from core.engine import SpecterEngine, ScanConfig

    config = ScanConfig(
        target_url         = "https://api.target.com",
        login_endpoint     = "/api/login",
        login_body         = '{"username":"admin","password":"admin"}',
        login_token_field  = "token",
        protected_endpoint = "/api/me",
        use_proxy          = True,          # route through Burp
        phases             = ["auth", "session"],  # run a subset
        output_dir         = "./reports",
    )
    engine   = SpecterEngine(config)
    findings = engine.run()
"""

from __future__ import annotations

import sys
import os
import json
import argparse
import traceback
import datetime
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

# ── internal imports ─────────────────────────────────────────────────────────
from utils.http_client import SpecterSession, make_session
from models.findings import ScanFinding, Severity

from core.auth_tester import AuthTester, AuthTarget
from core.logic_tester import LogicTester, LogicTarget, WorkflowStep
from core.session_analyzer import SessionAnalyzer, SessionTarget
from core.reporter import Reporter


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Colours — graceful degradation on non-ANSI terminals
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_ANSI = sys.stdout.isatty()

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _ANSI else text

RED     = lambda t: _c("31;1", t)
YELLOW  = lambda t: _c("33;1", t)
CYAN    = lambda t: _c("36;1", t)
GREEN   = lambda t: _c("32;1", t)
BOLD    = lambda t: _c("1",    t)
DIM     = lambda t: _c("2",    t)
MAGENTA = lambda t: _c("35;1", t)

SEVERITY_COLOR = {
    "critical": RED,
    "high":     YELLOW,
    "medium":   CYAN,
    "low":      GREEN,
    "info":     DIM,
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ScanConfig – unified configuration object passed to the engine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class ScanConfig:
    """
    All scan parameters in one place.  Mirrors the CLI flags 1-to-1.
    Only target_url is required; everything else has a safe default.
    """

    # ── core ─────────────────────────────────────────────────────────────────
    target_url:          str   = ""

    # ── auth / session endpoints ──────────────────────────────────────────────
    login_endpoint:      str   = "/login"
    login_body:          str   = '{"username":"admin","password":"admin"}'
    login_content_type:  str   = "application/json"
    login_token_field:   str   = "token"          # JSON path or "cookie:<name>"
    protected_endpoint:  str   = "/api/me"

    # ── password reset (auth phase) ───────────────────────────────────────────
    reset_endpoint:         str = ""
    reset_confirm_endpoint: str = ""
    reset_email_field:      str = "email"
    reset_test_email:       str = ""

    # ── logout / password change (session phase) ──────────────────────────────
    logout_endpoint:        str = ""
    change_pw_endpoint:     str = ""
    change_pw_body:         str = ""

    # ── business logic (logic phase) ──────────────────────────────────────────
    add_to_cart_endpoint:   str = ""
    add_to_cart_body:       str = ""
    checkout_endpoint:      str = ""
    profile_endpoint:       str = ""
    role_field:             str = "role"
    privileged_role:        str = "admin"
    coupon_endpoint:        str = ""
    coupon_code:            str = ""
    # Workflow steps can be injected programmatically (see SpecterEngine.set_workflow)
    workflow_steps:         List[WorkflowStep] = field(default_factory=list)

    # ── auth headers (sent with every request in logic/session phases) ─────────
    auth_headers:           Dict[str, str]   = field(default_factory=dict)

    # ── HTTP / proxy ──────────────────────────────────────────────────────────
    use_proxy:              bool  = False
    proxy_url:              str   = "http://127.0.0.1:8080"
    verify_ssl:             bool  = False
    timeout:                int   = 15

    # ── scan control ─────────────────────────────────────────────────────────
    phases:                 List[str] = field(default_factory=lambda: ["auth", "logic", "session"])
    scan_name:              str       = "Wraith Security Scan"
    output_dir:             str       = "./reports"
    no_report:              bool      = False   # skip writing files (useful in tests)
    verbose:                bool      = False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# SpecterEngine
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SpecterEngine:
    """
    Top-level orchestrator.  Instantiate with a ScanConfig, call run().
    Returns the full list of ScanFinding objects from all phases.
    """

    VERSION = "1.0.0"
    BANNER  = r"""
 ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗
 ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║
 ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║
 ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║
 ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝
  Auth · Logic · Session Security Scanner  v{version}
"""

    def __init__(self, config: ScanConfig, burp_callbacks: Any = None):
        self.config          = config
        self.burp_callbacks  = burp_callbacks   # set by Burp extension
        self.findings:       List[ScanFinding]  = []
        self._errors:        List[str]          = []
        self._session:       Optional[SpecterSession] = None

    # ── public surface ───────────────────────────────────────────────────────

    def set_workflow(self, steps: List[WorkflowStep]):
        """Inject ordered workflow steps for the logic-phase check."""
        self.config.workflow_steps = steps

    def run(self) -> List[ScanFinding]:
        """
        Execute all configured phases in order.
        Returns the aggregated finding list regardless of per-phase errors.
        """
        self._print_banner()
        self._session = self._build_session()

        phase_map = {
            "auth":    self._run_auth_phase,
            "logic":   self._run_logic_phase,
            "session": self._run_session_phase,
        }

        for phase_name in self.config.phases:
            fn = phase_map.get(phase_name)
            if fn is None:
                self._warn(f"Unknown phase '{phase_name}' — skipping")
                continue
            self._run_phase(phase_name, fn)

        self._print_summary()

        if not self.config.no_report:
            self._write_reports()

        return self.findings

    # ── phase runners ────────────────────────────────────────────────────────

    def _run_phase(self, name: str, fn):
        """Wrapper that times a phase, catches exceptions, and merges findings."""
        self._info(f"[{name.upper()}] Starting phase...")
        t0 = datetime.datetime.now(datetime.timezone.utc)
        try:
            phase_findings = fn()
            self.findings.extend(phase_findings)
            elapsed = (datetime.datetime.now(datetime.timezone.utc) - t0).total_seconds()
            self._info(
                f"[{name.upper()}] Done — "
                f"{GREEN(str(len(phase_findings)))} finding(s) in {elapsed:.1f}s"
            )
        except Exception as exc:
            elapsed = (datetime.datetime.now(datetime.timezone.utc) - t0).total_seconds()
            msg = f"[{name.upper()}] Phase failed after {elapsed:.1f}s: {exc}"
            self._error(msg)
            if self.config.verbose:
                traceback.print_exc()
            self._errors.append(msg)

    def _run_auth_phase(self) -> List[ScanFinding]:
        cfg = self.config
        target = AuthTarget(
            base_url                = cfg.target_url,
            login_endpoint          = cfg.login_endpoint,
            login_body              = cfg.login_body,
            login_content_type      = cfg.login_content_type,
            login_token_field       = cfg.login_token_field,
            protected_endpoint      = cfg.protected_endpoint,
            reset_endpoint          = cfg.reset_endpoint,
            reset_confirm_endpoint  = cfg.reset_confirm_endpoint,
            reset_email_field       = cfg.reset_email_field,
            reset_test_email        = cfg.reset_test_email,
        )
        tester = AuthTester(self._session, target)
        return tester.run_all()

    def _run_logic_phase(self) -> List[ScanFinding]:
        cfg = self.config

        # Merge any auth headers collected so far into the logic target
        auth_headers = dict(cfg.auth_headers)
        if self._session and self._session._base_headers.get("Authorization"):
            auth_headers.setdefault(
                "Authorization",
                self._session._base_headers["Authorization"]
            )

        target = LogicTarget(
            base_url             = cfg.target_url,
            auth_headers         = auth_headers,
            add_to_cart_endpoint = cfg.add_to_cart_endpoint,
            add_to_cart_body     = cfg.add_to_cart_body,
            checkout_endpoint    = cfg.checkout_endpoint,
            profile_endpoint     = cfg.profile_endpoint,
            role_field           = cfg.role_field,
            privileged_role      = cfg.privileged_role,
            coupon_endpoint      = cfg.coupon_endpoint,
            coupon_code          = cfg.coupon_code,
            workflow_steps       = cfg.workflow_steps,
        )
        tester = LogicTester(self._session, target)
        return tester.run_all()

    def _run_session_phase(self) -> List[ScanFinding]:
        cfg = self.config
        target = SessionTarget(
            base_url           = cfg.target_url,
            login_endpoint     = cfg.login_endpoint,
            login_body         = cfg.login_body,
            logout_endpoint    = cfg.logout_endpoint,
            protected_endpoint = cfg.protected_endpoint,
            change_pw_endpoint = cfg.change_pw_endpoint,
            change_pw_body     = cfg.change_pw_body,
            login_token_field  = cfg.login_token_field,
        )
        analyzer = SessionAnalyzer(self._session, target)
        return analyzer.run_all()

    # ── output helpers ───────────────────────────────────────────────────────

    def _write_reports(self):
        try:
            os.makedirs(self.config.output_dir, exist_ok=True)
            reporter = Reporter(
                findings        = self.findings,
                target_url      = self.config.target_url,
                scan_name       = self.config.scan_name,
                output_dir      = self.config.output_dir,
                scanner_version = self.VERSION,
            )
            json_path = reporter.write_json()
            html_path = reporter.write_html()
            self._info(f"Reports written:")
            self._info(f"  JSON → {CYAN(json_path)}")
            self._info(f"  HTML → {CYAN(html_path)}")
        except Exception as exc:
            self._error(f"Failed to write reports: {exc}")

    def _print_banner(self):
        banner = self.BANNER.format(version=self.VERSION)
        print(MAGENTA(banner))
        print(BOLD(f"  Target : {self.config.target_url}"))
        print(BOLD(f"  Phases : {', '.join(self.config.phases)}"))
        proxy_status = f"YES → {self.config.proxy_url}" if self.config.use_proxy else "NO"
        print(BOLD(f"  Proxy  : {proxy_status}"))
        print(DIM("  " + "─" * 60))
        print()

    def _print_summary(self):
        print()
        print(DIM("  " + "─" * 60))
        print(BOLD(f"\n  Scan complete — {len(self.findings)} finding(s) total\n"))

        sev_counts: Dict[str, int] = {}
        for f in self.findings:
            sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

        for sev in ("critical", "high", "medium", "low", "info"):
            count = sev_counts.get(sev, 0)
            if count:
                colour_fn = SEVERITY_COLOR.get(sev, str)
                label     = colour_fn(sev.upper().ljust(8))
                bar       = colour_fn("█" * min(count, 30))
                print(f"  {label}  {bar}  {count}")

        if self._errors:
            print()
            print(RED(f"  {len(self._errors)} phase error(s) — run with --verbose for stack traces"))

        print()

    # ── logging ──────────────────────────────────────────────────────────────

    def _info(self, msg: str):
        print(f"  {msg}")

    def _warn(self, msg: str):
        print(f"  {YELLOW('WARN')} {msg}")

    def _error(self, msg: str):
        print(f"  {RED('ERR ')} {msg}")

    # ── session factory ───────────────────────────────────────────────────────

    def _build_session(self) -> SpecterSession:
        if self.burp_callbacks is not None:
            # Inside Burp — route through Burp's engine
            return SpecterSession(burp_callbacks=self.burp_callbacks)

        return make_session(
            proxy      = self.config.proxy_url,
            use_proxy  = self.config.use_proxy,
            verify_ssl = self.config.verify_ssl,
            timeout    = self.config.timeout,
        )


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog        = "wraith",
        description = "Wraith — Auth · Logic · Session Security Scanner",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = """
examples:
  # Full scan through Burp proxy
  python -m core.engine --target https://api.target.com \\
    --login-endpoint /api/auth/login \\
    --login-body '{"username":"admin","password":"admin"}' \\
    --login-token-field token --protected-endpoint /api/me --proxy

  # Auth + session only, no proxy, verbose
  python -m core.engine --target https://target.com \\
    --phases auth session --verbose

  # Logic phase with cart/checkout endpoints
  python -m core.engine --target https://shop.target.com \\
    --phases logic \\
    --add-to-cart-endpoint /cart/add \\
    --add-to-cart-body '{"product_id":"1","quantity":1,"price":9.99}' \\
    --checkout-endpoint /checkout
        """,
    )

    # ── required ─────────────────────────────────────────────────────────────
    p.add_argument("--target", required=True, metavar="URL",
                   help="Base URL of the target (e.g. https://api.target.com)")

    # ── auth ─────────────────────────────────────────────────────────────────
    g_auth = p.add_argument_group("auth / session endpoints")
    g_auth.add_argument("--login-endpoint",     default="/login",
                        help="Login POST path (default: /login)")
    g_auth.add_argument("--login-body",         default='{"username":"admin","password":"admin"}',
                        help="Raw JSON body for login request")
    g_auth.add_argument("--login-content-type", default="application/json")
    g_auth.add_argument("--login-token-field",  default="token",
                        help="JSON key or 'cookie:<name>' that holds the issued token")
    g_auth.add_argument("--protected-endpoint", default="/api/me",
                        help="Endpoint that returns 200 only when authenticated")
    g_auth.add_argument("--reset-endpoint",        default="")
    g_auth.add_argument("--reset-confirm-endpoint", default="")
    g_auth.add_argument("--reset-email-field",     default="email")
    g_auth.add_argument("--reset-test-email",      default="")
    g_auth.add_argument("--logout-endpoint",       default="")
    g_auth.add_argument("--change-pw-endpoint",    default="")
    g_auth.add_argument("--change-pw-body",        default="")

    # ── logic ─────────────────────────────────────────────────────────────────
    g_logic = p.add_argument_group("business logic endpoints")
    g_logic.add_argument("--add-to-cart-endpoint", default="")
    g_logic.add_argument("--add-to-cart-body",     default="")
    g_logic.add_argument("--checkout-endpoint",    default="")
    g_logic.add_argument("--profile-endpoint",     default="")
    g_logic.add_argument("--role-field",           default="role")
    g_logic.add_argument("--privileged-role",      default="admin")
    g_logic.add_argument("--coupon-endpoint",      default="")
    g_logic.add_argument("--coupon-code",          default="")
    g_logic.add_argument("--auth-header",          metavar="NAME:VALUE", action="append",
                         dest="auth_headers", default=[],
                         help="Extra auth header for logic checks (repeatable). "
                              "e.g. --auth-header 'Authorization: Bearer <token>'")

    # ── scan control ─────────────────────────────────────────────────────────
    g_scan = p.add_argument_group("scan control")
    g_scan.add_argument("--phases", nargs="+", metavar="PHASE",
                        choices=["auth", "logic", "session"],
                        default=["auth", "logic", "session"],
                        help="Which phases to run (default: all)")
    g_scan.add_argument("--scan-name", default="Wraith Security Scan")
    g_scan.add_argument("--output-dir", default="./reports", metavar="DIR")
    g_scan.add_argument("--no-report", action="store_true",
                        help="Skip writing JSON/HTML report files")

    # ── HTTP ─────────────────────────────────────────────────────────────────
    g_http = p.add_argument_group("HTTP / proxy")
    g_http.add_argument("--proxy", action="store_true",
                        help="Route traffic through Burp on 127.0.0.1:8080")
    g_http.add_argument("--proxy-url", default="http://127.0.0.1:8080",
                        metavar="URL")
    g_http.add_argument("--timeout", type=int, default=15, metavar="SECS")

    # ── misc ──────────────────────────────────────────────────────────────────
    p.add_argument("--verbose", "-v", action="store_true")

    return p


def _parse_auth_headers(raw: List[str]) -> Dict[str, str]:
    """Convert ['Authorization: Bearer tok', 'X-Foo: bar'] → dict."""
    out: Dict[str, str] = {}
    for item in raw:
        if ":" in item:
            k, _, v = item.partition(":")
            out[k.strip()] = v.strip()
    return out


def main(argv: Optional[List[str]] = None):
    parser = _build_parser()
    args   = parser.parse_args(argv)

    config = ScanConfig(
        target_url              = args.target,
        login_endpoint          = args.login_endpoint,
        login_body              = args.login_body,
        login_content_type      = args.login_content_type,
        login_token_field       = args.login_token_field,
        protected_endpoint      = args.protected_endpoint,
        reset_endpoint          = args.reset_endpoint,
        reset_confirm_endpoint  = args.reset_confirm_endpoint,
        reset_email_field       = args.reset_email_field,
        reset_test_email        = args.reset_test_email,
        logout_endpoint         = args.logout_endpoint,
        change_pw_endpoint      = args.change_pw_endpoint,
        change_pw_body          = args.change_pw_body,
        add_to_cart_endpoint    = args.add_to_cart_endpoint,
        add_to_cart_body        = args.add_to_cart_body,
        checkout_endpoint       = args.checkout_endpoint,
        profile_endpoint        = args.profile_endpoint,
        role_field              = args.role_field,
        privileged_role         = args.privileged_role,
        coupon_endpoint         = args.coupon_endpoint,
        coupon_code             = args.coupon_code,
        auth_headers            = _parse_auth_headers(args.auth_headers),
        use_proxy               = args.proxy,
        proxy_url               = args.proxy_url,
        timeout                 = args.timeout,
        phases                  = args.phases,
        scan_name               = args.scan_name,
        output_dir              = args.output_dir,
        no_report               = args.no_report,
        verbose                 = args.verbose,
    )

    engine   = SpecterEngine(config)
    findings = engine.run()

    # Exit code reflects highest severity found
    sev_scores = {f.severity.score for f in findings}
    if not sev_scores:
        sys.exit(0)
    max_score = max(sev_scores)
    sys.exit(0 if max_score <= 1 else 1)   # exit 1 if anything above INFO


if __name__ == "__main__":
    # Allow running as:  python core/engine.py --target ...
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    main()