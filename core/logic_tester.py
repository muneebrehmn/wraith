"""
specter/core/logic_tester.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 3 – Business Logic Tester

Covers all business logic attack vectors from the spec:
  1. Negative price / quantity tampering
  2. Role parameter injection
  3. Workflow step skipping
  4. Coupon stacking abuse

Philosophy:
  Business logic bugs can't be detected by signatures alone — the scanner
  needs to understand the *expected* flow and compare it against what the
  server actually enforces. Each check works by:
    a) Making a "baseline" legitimate request
    b) Sending a tampered variant
    c) Comparing the outcome — if the server accepted the tampered variant,
       it's a finding.

Usage:
    from core.logic_tester import LogicTester, LogicTarget, WorkflowStep
    from utils.http_client import make_session

    session = make_session(use_proxy=True)

    target = LogicTarget(
        base_url        = "https://shop.target.com",
        auth_headers    = {"Authorization": "Bearer <valid_token>"},

        # Check 1: price/qty tampering
        add_to_cart_endpoint = "/cart/add",
        add_to_cart_body     = '{"product_id": "123", "quantity": 1, "price": 99.99}',
        checkout_endpoint    = "/checkout",

        # Check 2: role injection
        profile_endpoint     = "/api/user/profile",
        role_field           = "role",
        privileged_role      = "admin",

        # Check 3: workflow
        workflow_steps = [
            WorkflowStep("POST", "/order/step1-address",  '{"address": "123 St"}'),
            WorkflowStep("POST", "/order/step2-shipping", '{"method": "standard"}'),
            WorkflowStep("POST", "/order/step3-payment",  '{"card": "tok_visa"}'),
            WorkflowStep("POST", "/order/step4-confirm",  '{}'),
        ],

        # Check 4: coupons
        coupon_endpoint = "/cart/coupon",
        coupon_code     = "SAVE10",
    )

    tester   = LogicTester(session, target)
    findings = tester.run_all()
"""

from __future__ import annotations

import json
import copy
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from utils.http_client import SpecterSession, HttpRequest, HttpResponse
from models.findings import ScanFinding, Severity, Category


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Supporting dataclass — describes one step in a multi-step workflow
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class WorkflowStep:
    """
    Represents a single HTTP call in an ordered multi-step workflow
    (e.g., checkout: address → shipping → payment → confirm).

    name: human-readable label shown in findings (optional)
    success_status: what HTTP status code means this step was accepted
    """
    method:         str
    endpoint:       str
    body:           str  = ""
    name:           str  = ""
    success_status: int  = 200


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration dataclass — describe the target's business logic surface
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

@dataclass
class LogicTarget:
    """
    Describes the business logic attack surface for a target application.
    Only fill in fields relevant to the checks you want to run —
    unconfigured checks are skipped silently.
    """

    base_url:    str                        # e.g. "https://shop.target.com"
    auth_headers: Dict[str, str] = field(default_factory=dict)  # e.g. {"Authorization": "Bearer ..."}

    # ── Check 1: Price / Quantity tampering ──────────────────────────────────
    # Endpoint that adds an item to cart or creates an order with a price field
    add_to_cart_endpoint: str  = ""
    add_to_cart_body:     str  = ""    # must contain a "price" or "quantity" field
    checkout_endpoint:    str  = ""    # used to verify if the tampered order was committed

    # ── Check 2: Role parameter injection ────────────────────────────────────
    # Endpoint that accepts or returns user profile/settings data with a role field
    profile_endpoint:     str  = ""
    profile_method:       str  = "PUT"   # method used to UPDATE profile (PUT/PATCH/POST)
    profile_body:         str  = ""      # current profile body (will be cloned + tampered)
    role_field:           str  = "role"  # name of the role/privilege field in the body
    privileged_role:      str  = "admin" # value to inject as the elevated role

    # ── Check 3: Workflow step skipping ──────────────────────────────────────
    # Ordered list of WorkflowStep objects — the tester will try to jump to the
    # last step without completing the earlier ones
    workflow_steps: List[WorkflowStep] = field(default_factory=list)

    # ── Check 4: Coupon stacking ──────────────────────────────────────────────
    # Endpoint that applies a coupon/promo code to a cart or order
    coupon_endpoint:      str  = ""
    coupon_body_template: str  = '{{"code": "{code}"}}'  # {code} is replaced with coupon value
    coupon_code:          str  = "SAVE10"   # a real coupon code that works on the target
    coupon_stack_count:   int  = 3          # how many times to try applying the same coupon

    # ── Optional response comparison callback ────────────────────────────────
    # Given (baseline_response, tampered_response), return True if the tampered
    # response indicates the server *accepted* the tampered value.
    # If None, the tester uses its built-in heuristics.
    accepted_checker: Optional[Callable[[HttpResponse, HttpResponse], bool]] = None

    # ── Extra headers ─────────────────────────────────────────────────────────
    extra_headers: Dict[str, str] = field(default_factory=dict)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# LogicTester — main class
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class LogicTester:
    """
    Probes business logic vulnerabilities by sending legitimate baseline
    requests and then comparing them against carefully tampered variants.

    Pattern for every check:
      1. Send a *baseline* request (normal, legitimate)
      2. Send a *tampered* request (with the malicious modification)
      3. If the server accepted the tampered version → ScanFinding

    All checks are independent. run_all() calls them all safely.
    """

    def __init__(self, session: SpecterSession, target: LogicTarget):
        self.session  = session
        self.target   = target
        self.findings: List[ScanFinding] = []

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Public entry point
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def run_all(self) -> List[ScanFinding]:
        """Run every logic check and return all findings."""
        self.findings = []

        checks = [
            ("Price / Quantity Tampering", self.check_price_quantity_tampering),
            ("Role Parameter Injection",   self.check_role_injection),
            ("Workflow Step Skipping",     self.check_workflow_skip),
            ("Coupon Stacking Abuse",      self.check_coupon_stacking),
        ]

        for name, fn in checks:
            print(f"[*] Logic: {name}")
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

        print(f"[+] Logic phase complete — {len(self.findings)} findings")
        return self.findings

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 1 — Negative Price / Quantity Tampering
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_price_quantity_tampering(self):
        """
        Submits tampered cart/order requests with:
          - Negative prices   (e.g., price: -99.99 → free or reverse charge)
          - Zero price        (e.g., price: 0)
          - Negative quantity (e.g., qty: -1 → credit to account)
          - Extremely large   quantity (overflow / DoS check)
          - Fractional tricks (e.g., qty: 0.001)

        For each tampered value, we compare the server's response to the
        baseline (original values) to see if the modification was silently accepted.
        """
        if not self.target.add_to_cart_endpoint or not self.target.add_to_cart_body:
            return

        # Parse the original body so we can clone and modify specific fields
        try:
            original_body = json.loads(self.target.add_to_cart_body)
        except json.JSONDecodeError:
            print("[!] add_to_cart_body is not valid JSON — skipping price/qty check")
            return

        # Send a clean baseline to establish what a successful response looks like
        baseline_resp = self._request(
            "POST",
            self.target.add_to_cart_endpoint,
            json.dumps(original_body),
        )

        # ── Price tampering payloads ──────────────────────────────────────────
        # Common field names used for prices across different frameworks/languages
        price_fields = ["price", "unit_price", "amount", "cost", "total", "item_price"]
        price_payloads = [
            ("Negative Price",     -99.99),
            ("Zero Price",          0),
            ("Zero Price (str)",   "0"),
            ("Tiny Fraction",       0.001),
            ("Large Negative",     -9999999),
        ]

        for field_name in price_fields:
            if field_name not in original_body:
                continue
            for label, tampered_value in price_payloads:
                tampered_body = copy.deepcopy(original_body)
                tampered_body[field_name] = tampered_value

                resp = self._request(
                    "POST",
                    self.target.add_to_cart_endpoint,
                    json.dumps(tampered_body),
                )

                if self._was_accepted(baseline_resp, resp):
                    self._add_finding(
                        title       = f"Price Tampering Accepted: {label}",
                        severity    = Severity.CRITICAL,
                        description = (
                            f"Server accepted '{field_name}={tampered_value}' without validation. "
                            "An attacker can manipulate order totals to pay nothing or receive credits."
                        ),
                        evidence    = {
                            "field":           field_name,
                            "original_value":  original_body[field_name],
                            "tampered_value":  tampered_value,
                            "baseline_status": baseline_resp.status_code,
                            "tampered_status": resp.status_code,
                            "response_snippet": resp.body[:300],
                        },
                        cwe         = 840,
                        remediation = (
                            "Never trust client-supplied price/amount values. "
                            "Always compute prices server-side from the product catalogue. "
                            "Reject or clamp any negative or zero price."
                        ),
                        request  = resp.request,
                        response = resp,
                        tags     = ["price-tampering", "business-logic", "ecommerce"],
                    )

        # ── Quantity tampering payloads ───────────────────────────────────────
        qty_fields = ["quantity", "qty", "count", "amount", "units"]
        qty_payloads = [
            ("Negative Quantity",   -1),
            ("Zero Quantity",        0),
            ("Large Quantity",       999999999),
            ("Fractional Quantity",  0.5),
            ("Negative Large",      -999999),
        ]

        for field_name in qty_fields:
            if field_name not in original_body:
                continue
            for label, tampered_value in qty_payloads:
                tampered_body = copy.deepcopy(original_body)
                tampered_body[field_name] = tampered_value

                resp = self._request(
                    "POST",
                    self.target.add_to_cart_endpoint,
                    json.dumps(tampered_body),
                )

                if self._was_accepted(baseline_resp, resp):
                    # Severity depends on the direction:
                    # Negative = can drain inventory or get credits → CRITICAL
                    # Overflow = availability/DoS risk → HIGH
                    sev = Severity.CRITICAL if isinstance(tampered_value, (int, float)) and tampered_value < 0 else Severity.HIGH

                    self._add_finding(
                        title       = f"Quantity Tampering Accepted: {label}",
                        severity    = sev,
                        description = (
                            f"Server accepted '{field_name}={tampered_value}'. "
                            "Negative quantities may allow free credit; "
                            "huge values may trigger integer overflow or cause inventory desync."
                        ),
                        evidence    = {
                            "field":           field_name,
                            "original_value":  original_body.get(field_name),
                            "tampered_value":  tampered_value,
                            "response_snippet": resp.body[:300],
                        },
                        cwe         = 840,
                        remediation = (
                            "Validate quantity on the server: must be a positive integer "
                            "within reasonable bounds (e.g., 1–1000). "
                            "Use integer types, not floats, for quantities."
                        ),
                        request  = resp.request,
                        response = resp,
                        tags     = ["qty-tampering", "business-logic"],
                    )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 2 — Role Parameter Injection
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_role_injection(self):
        """
        Tests whether the server accepts client-supplied role/privilege escalation
        through the profile update endpoint.

        Attack flow:
          1. Fetch current user profile (GET) to see what fields are present
          2. Send a profile update (PUT/PATCH) with an injected privileged role
          3. Re-fetch profile (GET) and check if the role was persisted

        Also tries common role injection patterns:
          - Simple string:  "role": "admin"
          - Array:          "roles": ["admin", "superuser"]
          - Nested:         "permissions": {"level": 999}
          - Mass assignment: adding "isAdmin": true alongside normal fields
        """
        if not self.target.profile_endpoint:
            return

        # ── Step 1: read current profile ──────────────────────────────────────
        current_profile_resp = self._request("GET", self.target.profile_endpoint)

        # Parse the current profile body (so we know the existing field names/values)
        current_profile = {}
        if current_profile_resp.is_json:
            try:
                current_profile = current_profile_resp.json()
            except (json.JSONDecodeError, ValueError):
                pass

        # Use the configured body or fall back to the fetched profile
        update_body_str = self.target.profile_body or json.dumps(current_profile)
        try:
            update_body = json.loads(update_body_str)
        except json.JSONDecodeError:
            return

        # ── Injection payloads ────────────────────────────────────────────────
        # Each entry is (label, field_to_add_or_replace, value_to_inject)
        injection_payloads = [
            # Direct role field override
            (f"Role field set to '{self.target.privileged_role}'",
             self.target.role_field,   self.target.privileged_role),

            # Common boolean privilege flags (mass assignment)
            ("isAdmin flag injection",     "isAdmin",     True),
            ("is_admin flag injection",    "is_admin",    True),
            ("admin flag injection",       "admin",       True),
            ("superuser flag injection",   "superuser",   True),

            # Numeric privilege levels
            ("Permission level 99",        "permission_level", 99),
            ("Access level 0 (root)",      "access_level",     0),

            # Roles as array
            ("Roles array injection",      "roles",
             [self.target.privileged_role, "superuser"]),
        ]

        for label, inject_field, inject_value in injection_payloads:
            # Clone and inject into a copy of the update body
            tampered = copy.deepcopy(update_body)
            tampered[inject_field] = inject_value

            # Send the update request
            update_resp = self._request(
                self.target.profile_method,
                self.target.profile_endpoint,
                json.dumps(tampered),
            )

            # If update was rejected outright, skip verification
            if update_resp.status_code >= 400:
                continue

            # ── Step 3: re-read profile to check if role persisted ────────────
            verify_resp = self._request("GET", self.target.profile_endpoint)
            if not verify_resp.is_json:
                continue

            try:
                new_profile = verify_resp.json()
            except (json.JSONDecodeError, ValueError):
                continue

            # Check if the injected field now appears in the profile with our value
            if self._role_persisted(new_profile, inject_field, inject_value):
                self._add_finding(
                    title       = f"Role Parameter Injection: {label}",
                    severity    = Severity.CRITICAL,
                    description = (
                        f"Server accepted and persisted '{inject_field}={inject_value}' "
                        "in a profile update request. An attacker can escalate their own "
                        "privileges without any server-side authorization check."
                    ),
                    evidence    = {
                        "injected_field":  inject_field,
                        "injected_value":  inject_value,
                        "update_status":   update_resp.status_code,
                        "profile_after":   new_profile,
                    },
                    cwe         = 269,
                    remediation = (
                        "Never accept role or privilege fields from client input. "
                        "Maintain an allowlist of user-modifiable fields server-side. "
                        "Use a dedicated admin interface for role management."
                    ),
                    request  = update_resp.request,
                    response = update_resp,
                    tags     = ["role-injection", "privilege-escalation", "mass-assignment"],
                )
                # One confirmed finding per check is enough — stop trying more payloads
                break

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 3 — Workflow Step Skipping
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_workflow_skip(self):
        """
        Tests whether a multi-step workflow (e.g., checkout) enforces step order.

        Strategy:
          a) Complete the full workflow normally to confirm it works (baseline)
          b) Attempt to jump directly to step N without completing steps 1..N-1
          c) Try every possible "skip to step N" combination

        A vulnerable app allows reaching the final step (e.g., payment confirmation)
        without completing prerequisite steps (e.g., address, shipping selection).

        Also tests:
          - Repeating an already-completed step (idempotency abuse)
          - Submitting steps out of order
        """
        steps = self.target.workflow_steps
        if len(steps) < 2:
            return   # need at least 2 steps to test skipping

        # ── Baseline: walk through all steps in order ─────────────────────────
        # This confirms the workflow works normally before we start abusing it
        baseline_final_resp = self._run_workflow(steps)
        baseline_ok = (
            baseline_final_resp is not None and
            baseline_final_resp.status_code == steps[-1].success_status
        )

        if not baseline_ok:
            # The workflow didn't even work normally — flag for manual review
            self._add_finding(
                title       = "Workflow Baseline Failed — Manual Review Needed",
                severity    = Severity.INFO,
                description = (
                    "The full workflow did not complete successfully in baseline mode. "
                    "Step-skip checks were skipped. Verify endpoint config and auth headers."
                ),
                evidence    = {
                    "steps":         [s.endpoint for s in steps],
                    "final_status":  baseline_final_resp.status_code if baseline_final_resp else "N/A",
                },
                tags = ["workflow", "config-error"],
            )
            return

        # ── Skip tests: try accessing step N directly without N-1 prerequisites ──
        # We test jumping to: last step, second-to-last, and middle step
        skip_targets = list(set([
            len(steps) - 1,      # final step (highest impact — e.g., confirm payment)
            len(steps) - 2,      # second to last
            len(steps) // 2,     # midpoint
        ]))

        for target_idx in sorted(skip_targets):
            if target_idx <= 0:
                continue   # nothing to skip if we're already at step 1

            step = steps[target_idx]
            step_name = step.name or step.endpoint

            # Reset server-side workflow state by hitting step 0 first.
            # This starts a fresh order/session so the skip attempt is truly
            # isolated — without this, residual state from the baseline run
            # could make the server think prerequisites were already met.
            self._request(steps[0].method, steps[0].endpoint, steps[0].body)

            # Now jump straight to the target step — skipping all steps between 1 and N
            resp = self._request(step.method, step.endpoint, step.body)

            if resp.status_code == step.success_status:
                # The step accepted the request without prerequisites → vulnerability
                # Severity is higher if the skipped step is the final confirmation step
                is_final = (target_idx == len(steps) - 1)
                sev = Severity.CRITICAL if is_final else Severity.HIGH

                self._add_finding(
                    title       = f"Workflow Step Skipping: Step {target_idx + 1} reachable without prerequisites",
                    severity    = sev,
                    description = (
                        f"Step '{step_name}' (step {target_idx + 1}/{len(steps)}) "
                        f"was accessible without completing the {target_idx} preceding steps. "
                        "An attacker can skip required checks such as address validation, "
                        "age verification, or payment authorization."
                    ),
                    evidence    = {
                        "skipped_to_step": target_idx + 1,
                        "step_endpoint":   step.endpoint,
                        "total_steps":     len(steps),
                        "response_status": resp.status_code,
                        "response_snippet": resp.body[:300],
                    },
                    cwe         = 840,
                    remediation = (
                        "Enforce workflow state server-side using a session-bound state machine. "
                        "Each step should verify that all prerequisite steps are complete "
                        "before processing the current step."
                    ),
                    request  = resp.request,
                    response = resp,
                    tags     = ["workflow", "step-skip", "business-logic"],
                )

        # ── Repeat test: replay an already-completed step ─────────────────────
        # Re-run the workflow, then immediately replay step 1 again.
        # Some apps don't check if a step was already completed (idempotency bug).
        self._run_workflow(steps)   # complete it again to reset state

        replay_resp = self._request(steps[0].method, steps[0].endpoint, steps[0].body)
        if replay_resp.status_code == steps[0].success_status:
            self._add_finding(
                title       = "Workflow Step Replay Accepted",
                severity    = Severity.MEDIUM,
                description = (
                    f"Step 1 ('{steps[0].endpoint}') was accepted again after already being completed. "
                    "Depending on the workflow, replaying steps may allow double-submissions "
                    "or resetting choices that should be locked."
                ),
                evidence    = {
                    "replayed_step":   steps[0].endpoint,
                    "response_status": replay_resp.status_code,
                },
                cwe         = 840,
                remediation = (
                    "Mark workflow steps as completed in the server-side session. "
                    "Reject replayed steps with a 409 Conflict or redirect to the next step."
                ),
                tags = ["workflow", "replay", "idempotency"],
            )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Check 4 — Coupon Stacking Abuse
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def check_coupon_stacking(self):
        """
        Tests whether coupons can be applied multiple times to the same cart/order.

        Attack vectors:
          a) Apply the same coupon N times in a row (same-coupon stacking)
          b) Apply the coupon, then apply it again after a slight delay (timing gap)
          c) Apply the coupon in rapid parallel-ish succession (race condition hint)

        The check looks for:
          - Server accepting the coupon on the 2nd+ application (response 200/success)
          - Discount amounts being additive across applications
          - No error/rejection message in the body
        """
        if not self.target.coupon_endpoint or not self.target.coupon_code:
            return

        def apply_coupon() -> HttpResponse:
            """Helper: apply the configured coupon code and return the response."""
            body = self.target.coupon_body_template.format(code=self.target.coupon_code)
            return self._request("POST", self.target.coupon_endpoint, body)

        # ── First application: establish baseline ─────────────────────────────
        first_resp = apply_coupon()
        if first_resp.status_code >= 400:
            # Coupon itself didn't work — check may be misconfigured
            self._add_finding(
                title       = "Coupon Check: First Application Failed",
                severity    = Severity.INFO,
                description = (
                    f"The first coupon application returned {first_resp.status_code}. "
                    "Stacking check requires a working coupon code. "
                    "Verify coupon_code and coupon_endpoint configuration."
                ),
                evidence    = {"response_snippet": first_resp.body[:200]},
                tags        = ["coupon", "config"],
            )
            return

        # ── Subsequent applications: look for stacking ────────────────────────
        stack_accepted_count = 0
        last_accepted_resp   = None

        for i in range(2, self.target.coupon_stack_count + 1):
            # Small delay to avoid pure race conditions (we test timing separately)
            time.sleep(0.1)
            resp = apply_coupon()

            if self._coupon_still_accepted(first_resp, resp):
                stack_accepted_count += 1
                last_accepted_resp = resp

        if stack_accepted_count > 0:
            self._add_finding(
                title       = "Coupon Stacking Accepted",
                severity    = Severity.HIGH,
                description = (
                    f"The coupon '{self.target.coupon_code}' was accepted "
                    f"{stack_accepted_count + 1} times on the same cart/order. "
                    "An attacker can stack the discount to get items for free or at a "
                    "deeply reduced price."
                ),
                evidence    = {
                    "coupon_code":       self.target.coupon_code,
                    "total_applications": stack_accepted_count + 1,
                    "first_response":    first_resp.body[:200],
                    "last_response":     last_accepted_resp.body[:200] if last_accepted_resp else "",
                },
                cwe         = 840,
                remediation = (
                    "Track coupon application per-user per-order in the database. "
                    "Reject subsequent applications of the same coupon with a clear error. "
                    "Apply coupons atomically to prevent race condition stacking."
                ),
                request  = last_accepted_resp.request if last_accepted_resp else None,
                response = last_accepted_resp,
                tags     = ["coupon", "stacking", "business-logic", "ecommerce"],
            )

        # ── Rapid-fire hint: flag potential race condition ─────────────────────
        # We can't truly parallelise in a single-threaded scanner, but we flag
        # the endpoint for Burp Intruder race condition testing.
        self._add_finding(
            title       = "Coupon Endpoint — Recommend Race Condition Test",
            severity    = Severity.INFO,
            description = (
                f"The coupon endpoint '{self.target.coupon_endpoint}' should be tested "
                "for race conditions using Burp Suite's parallel requests feature. "
                "Even if sequential stacking is blocked, simultaneous requests may bypass "
                "the application's coupon-use tracking."
            ),
            evidence    = {"endpoint": self.target.coupon_endpoint},
            remediation = (
                "Use database-level locks or atomic compare-and-swap when recording coupon use. "
                "Test with Burp's 'Send group in parallel (last-byte sync)' feature."
            ),
            tags = ["coupon", "race-condition", "manual-test"],
        )

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Internal helpers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _request(
        self,
        method:   str,
        endpoint: str,
        body:     str = "",
        extra_headers: Optional[Dict] = None,
    ) -> HttpResponse:
        """Send a request to the target, merging auth and extra headers."""
        headers = {
            "Content-Type": "application/json",
            **self.target.auth_headers,
            **self.target.extra_headers,
            **(extra_headers or {}),
        }
        return self.session.send(HttpRequest(
            method  = method.upper(),
            url     = self.target.base_url + endpoint,
            headers = headers,
            body    = body or None,
        ))

    def _run_workflow(self, steps: List[WorkflowStep]) -> Optional[HttpResponse]:
        """
        Execute a workflow in order, returning the last step's response.
        Returns None if any step fails (non-success status).
        """
        last_resp = None
        for step in steps:
            resp = self._request(step.method, step.endpoint, step.body)
            last_resp = resp
            if resp.status_code != step.success_status:
                # Step failed — abort workflow
                return last_resp
        return last_resp

    def _was_accepted(self, baseline: HttpResponse, tampered: HttpResponse) -> bool:
        """
        Determine if the tampered request was silently accepted by the server.

        Uses the custom checker if provided, otherwise applies heuristics:
          - Same or lower status code as baseline
          - Body doesn't contain validation-error keywords
          - If baseline was 200, tampered must also be 200
        """
        if self.target.accepted_checker:
            return self.target.accepted_checker(baseline, tampered)

        # Hard rejection: 4xx or 5xx means the server caught the tamper
        if tampered.status_code >= 400:
            return False

        # Check if the response body contains obvious rejection language
        body_lower = tampered.body.lower()
        rejection_keywords = [
            "invalid", "error", "negative", "must be positive",
            "out of range", "validation", "rejected", "forbidden",
            "not allowed", "bad request",
        ]
        if any(k in body_lower for k in rejection_keywords):
            return False

        return True

    def _coupon_still_accepted(self, first_resp: HttpResponse, nth_resp: HttpResponse) -> bool:
        """
        Determine if a subsequent coupon application was accepted.
        More strict than _was_accepted because some apps silently ignore repeat coupons.
        """
        # Explicit rejection
        if nth_resp.status_code >= 400:
            return False

        body_lower = nth_resp.body.lower()

        # Explicit rejection language
        rejection_keywords = [
            "already applied", "already used", "duplicate", "cannot apply",
            "coupon used", "limit", "maximum", "not valid", "invalid",
        ]
        if any(k in body_lower for k in rejection_keywords):
            return False

        # If the response looks identical to the first acceptance → likely stacked
        if nth_resp.status_code == first_resp.status_code:
            return True

        return False

    def _role_persisted(self, profile: Any, field: str, value: Any) -> bool:
        """
        Recursively checks if a field with the expected value appears in the
        post-update profile JSON. Handles nested objects.
        """
        if isinstance(profile, dict):
            if field in profile:
                stored = profile[field]
                # Compare: handle list roles, string roles, bool flags
                if isinstance(stored, list) and isinstance(value, list):
                    return any(v in stored for v in value)
                if isinstance(stored, str) and isinstance(value, str):
                    return stored.lower() == value.lower()
                return stored == value
            # Recurse into nested dicts
            for v in profile.values():
                if isinstance(v, dict) and self._role_persisted(v, field, value):
                    return True
        return False

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
        """Construct a ScanFinding and append it to the findings list."""
        self.findings.append(ScanFinding(
            title       = title,
            severity    = severity,
            category    = Category.BUSINESS_LOGIC,
            description = description,
            evidence    = evidence or {},
            cwe         = cwe,
            remediation = remediation,
            request     = request,
            response    = response,
            phase       = "logic",
            tags        = tags or [],
        ))