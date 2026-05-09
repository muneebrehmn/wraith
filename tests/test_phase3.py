"""
specter/tests/test_phase3.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 3 tests — LogicTester (no real network)
Run: python -m pytest tests/test_phase3.py -v
"""

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import json
from typing import Dict, Optional

from utils.http_client import HttpRequest, HttpResponse
from core.logic_tester import LogicTester, LogicTarget, WorkflowStep
from models.findings import Severity


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Mock infrastructure (reused from Phase 2 pattern)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def mock_response(status=200, body="{}", headers=None, req=None) -> HttpResponse:
    return HttpResponse(
        status_code = status,
        headers     = headers or {"content-type": "application/json"},
        body        = body,
        elapsed_ms  = 5.0,
        request     = req or HttpRequest("POST", "http://t/"),
    )


class MockSession:
    """
    Scriptable mock session.
    route_fn: callable(HttpRequest) → HttpResponse for full control.
    routes dict: {"/path": HttpResponse} for simple cases.
    """
    def __init__(self, routes=None, route_fn=None):
        self.routes   = routes or {}
        self.route_fn = route_fn
        self.history  = []
        self.calls: list = []   # log every request for assertion

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
            resp = resp or mock_response(200, "{}")
        resp.request = req
        self.history.append(resp)
        return resp


def _base_target(**kwargs) -> LogicTarget:
    return LogicTarget(base_url="http://shop.test", **kwargs)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Price / Quantity Tampering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestPriceTampering:

    def _tester(self, cart_status=200, cart_body='{"order_id":"1"}', reject_negatives=False):
        """
        reject_negatives=True → simulate a server that catches negative prices.
        reject_negatives=False → server silently accepts everything (vulnerable).
        """
        def route(req: HttpRequest) -> HttpResponse:
            if "/cart" in req.url and req.body:
                try:
                    data = json.loads(req.body)
                    price = data.get("price", 1)
                    qty   = data.get("quantity", 1)
                    # Simulate a server that rejects negatives
                    if reject_negatives and (
                        (isinstance(price, (int, float)) and price < 0) or
                        (isinstance(qty,   (int, float)) and qty   < 0)
                    ):
                        return mock_response(400, '{"error": "invalid value"}')
                except Exception:
                    pass
            return mock_response(cart_status, cart_body)

        session = MockSession(route_fn=route)
        target  = _base_target(
            add_to_cart_endpoint = "/cart/add",
            add_to_cart_body     = json.dumps({"product_id": "1", "price": 9.99, "quantity": 1}),
        )
        return LogicTester(session, target)

    def test_negative_price_flagged(self):
        tester = self._tester(reject_negatives=False)
        tester.run_all()
        assert any("Price Tampering" in f.title for f in tester.findings)

    def test_negative_price_not_flagged_when_rejected(self):
        tester = self._tester(reject_negatives=True)
        tester.run_all()
        price_findings = [f for f in tester.findings if "Price Tampering" in f.title and "Negative" in f.title]
        assert len(price_findings) == 0

    def test_negative_qty_flagged(self):
        tester = self._tester(reject_negatives=False)
        tester.run_all()
        assert any("Quantity Tampering" in f.title for f in tester.findings)

    def test_critical_severity_for_negative_qty(self):
        tester = self._tester(reject_negatives=False)
        tester.run_all()
        negative_qty = [
            f for f in tester.findings
            if "Quantity Tampering" in f.title and "Negative" in f.title
        ]
        assert all(f.severity == Severity.CRITICAL for f in negative_qty)

    def test_no_findings_on_non_json_body(self):
        """Non-JSON cart body → check is skipped, no crash."""
        session = MockSession(routes={"/cart": mock_response(200)})
        target  = _base_target(
            add_to_cart_endpoint = "/cart/add",
            add_to_cart_body     = "not=json&body=1",
        )
        tester = LogicTester(session, target)
        tester.run_all()   # should not raise


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Role Parameter Injection
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestRoleInjection:

    def _make_session(self, persists_role: bool):
        """
        persists_role=True  → GET /profile after PUT returns whatever was PUT (vulnerable).
        persists_role=False → GET /profile always returns original non-admin role (secure).
        """
        # Shared mutable state to simulate server storing the profile
        stored = {"username": "alice", "role": "user", "email": "a@a.com"}

        def route(req: HttpRequest) -> HttpResponse:
            nonlocal stored
            if "/profile" in req.url:
                if req.method == "GET":
                    return mock_response(200, json.dumps(stored))
                if req.method in ("PUT", "PATCH", "POST") and req.body:
                    try:
                        incoming = json.loads(req.body)
                        if persists_role:
                            stored = {**stored, **incoming}  # mass assignment — vulnerable
                        else:
                            # Only allow safe fields
                            for safe in ("email", "username"):
                                if safe in incoming:
                                    stored[safe] = incoming[safe]
                    except Exception:
                        pass
                    return mock_response(200, json.dumps(stored))
            return mock_response(404, "{}")

        return MockSession(route_fn=route)

    def test_role_injection_detected(self):
        session = self._make_session(persists_role=True)
        target  = _base_target(
            profile_endpoint = "/profile",
            profile_method   = "PUT",
            role_field       = "role",
            privileged_role  = "admin",
        )
        tester = LogicTester(session, target)
        tester.run_all()
        assert any("Role Parameter Injection" in f.title for f in tester.findings)
        critical = [f for f in tester.findings if f.severity == Severity.CRITICAL]
        assert any("Role" in f.title for f in critical)

    def test_role_injection_not_flagged_when_blocked(self):
        session = self._make_session(persists_role=False)
        target  = _base_target(
            profile_endpoint = "/profile",
            profile_method   = "PUT",
            role_field       = "role",
            privileged_role  = "admin",
        )
        tester = LogicTester(session, target)
        tester.run_all()
        assert not any("Role Parameter Injection" in f.title for f in tester.findings)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Workflow Step Skipping
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestWorkflowSkip:

    STEPS = [
        WorkflowStep("POST", "/checkout/address",  '{"address":"123 St"}',  "Address",  200),
        WorkflowStep("POST", "/checkout/shipping",  '{"method":"std"}',      "Shipping", 200),
        WorkflowStep("POST", "/checkout/payment",   '{"card":"tok_visa"}',   "Payment",  200),
        WorkflowStep("POST", "/checkout/confirm",   '{}',                    "Confirm",  200),
    ]

    def _session(self, enforce_order: bool):
        """
        enforce_order=True  → only allow steps if previous steps were seen (secure).
        enforce_order=False → every step always returns 200 (vulnerable).

        Resets visited state whenever step 0 (first step) is called again,
        simulating a fresh order/session — so skip attempts start with clean state.
        """
        state = {"visited": set()}

        def route(req: HttpRequest) -> HttpResponse:
            path = req.url.split("http://shop.test")[1]
            idx  = next((i for i, s in enumerate(self.STEPS) if s.endpoint == path), None)

            if idx is None:
                return mock_response(404)

            # Reset on first step — new order begins (baseline run resets state for skip tests)
            if idx == 0:
                state["visited"] = set()

            if enforce_order and idx > 0:
                prev_endpoint = self.STEPS[idx - 1].endpoint
                if prev_endpoint not in state["visited"]:
                    return mock_response(400, '{"error": "complete previous steps first"}')

            state["visited"].add(path)
            return mock_response(200, '{"ok": true}')

        return MockSession(route_fn=route)

    def test_skip_detected_on_vulnerable_app(self):
        session = self._session(enforce_order=False)
        target  = _base_target(workflow_steps=self.STEPS)
        tester  = LogicTester(session, target)
        tester.run_all()
        assert any("Step Skipping" in f.title for f in tester.findings)

    def test_final_step_skip_is_critical(self):
        session = self._session(enforce_order=False)
        target  = _base_target(workflow_steps=self.STEPS)
        tester  = LogicTester(session, target)
        tester.run_all()
        final_skip = [
            f for f in tester.findings
            if "Step Skipping" in f.title and "4" in f.title   # step 4 = confirm
        ]
        assert all(f.severity == Severity.CRITICAL for f in final_skip)

    def test_no_skip_finding_on_secure_app(self):
        session = self._session(enforce_order=True)
        target  = _base_target(workflow_steps=self.STEPS)
        tester  = LogicTester(session, target)
        tester.run_all()
        assert not any("Step Skipping" in f.title for f in tester.findings)

    def test_less_than_two_steps_skipped_safely(self):
        session = MockSession(routes={"/only": mock_response(200)})
        target  = _base_target(workflow_steps=[WorkflowStep("POST", "/only", "")])
        tester  = LogicTester(session, target)
        tester.run_all()   # should not raise or add skip findings


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Coupon Stacking
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TestCouponStacking:

    def _session(self, max_uses: int = 1):
        """max_uses: how many times the coupon is accepted before rejection."""
        use_count = {"n": 0}

        def route(req: HttpRequest) -> HttpResponse:
            if "/coupon" in req.url:
                use_count["n"] += 1
                if use_count["n"] <= max_uses:
                    return mock_response(200, '{"discount": 10}')
                return mock_response(400, '{"error": "coupon already used"}')
            return mock_response(200)

        return MockSession(route_fn=route)

    def test_stacking_detected_when_accepted_twice(self):
        session = self._session(max_uses=99)
        target  = _base_target(
            coupon_endpoint    = "/coupon/apply",
            coupon_code        = "SAVE10",
            coupon_stack_count = 3,
        )
        tester = LogicTester(session, target)
        tester.run_all()
        assert any("Coupon Stacking" in f.title for f in tester.findings)

    def test_stacking_not_flagged_when_second_use_rejected(self):
        session = self._session(max_uses=1)
        target  = _base_target(
            coupon_endpoint    = "/coupon/apply",
            coupon_code        = "SAVE10",
            coupon_stack_count = 3,
        )
        tester = LogicTester(session, target)
        tester.run_all()
        assert not any("Coupon Stacking Accepted" in f.title for f in tester.findings)

    def test_race_condition_info_always_added(self):
        """The race-condition informational finding should always appear after a working coupon."""
        session = self._session(max_uses=99)
        target  = _base_target(
            coupon_endpoint    = "/coupon/apply",
            coupon_code        = "SAVE10",
            coupon_stack_count = 2,
        )
        tester = LogicTester(session, target)
        tester.run_all()
        assert any("Race Condition" in f.title for f in tester.findings)

    def test_first_application_failure_flagged_as_info(self):
        session = self._session(max_uses=0)
        target  = _base_target(
            coupon_endpoint = "/coupon/apply",
            coupon_code     = "BADCODE",
        )
        tester = LogicTester(session, target)
        tester.run_all()
        assert any("First Application Failed" in f.title for f in tester.findings)


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v", "--tb=short"])