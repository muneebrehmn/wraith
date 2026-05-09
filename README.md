# Wraith

> **Auth · Logic · Session Security Scanner**  
> A dual-mode web security testing framework specialising in authentication flow weaknesses, business logic flaws, and session handling vulnerabilities.

---

## What It Does

Specter automates the class of vulnerabilities that automated scanners consistently miss — the ones that require understanding application flow, not just pattern matching:

| Phase | Attack Vectors |
|-------|---------------|
| **Auth** | JWT none-algorithm bypass, RS256→HS256 algorithm confusion, token entropy analysis, weak secret cracking, password reset token reuse, response-based auth bypass |
| **Logic** | Negative price/quantity tampering, role parameter injection, workflow step skipping, coupon stacking abuse |
| **Session** | Post-logout token reuse, session fixation, concurrent session abuse, no invalidation on password change |

---

## Architecture

```
specter/
├── core/
│   ├── engine.py            # Orchestrator + CLI entry point
│   ├── auth_tester.py       # Phase 2 — authentication attacks
│   ├── logic_tester.py      # Phase 3 — business logic attacks
│   ├── session_analyzer.py  # Phase 4 — session management attacks
│   └── reporter.py          # Phase 5 — JSON + HTML output
├── burp_extension/
│   └── authlogic_burp.py    # Jython wrapper — runs inside Burp Suite
├── models/
│   └── findings.py          # Shared ScanFinding data model
└── utils/
    ├── http_client.py        # Dual-mode HTTP client (requests / Burp shim)
    └── token_analyzer.py     # JWT analysis, entropy, cookie flag auditing
```

The HTTP layer is **dual-mode**: in standalone mode it uses `requests`; loaded as a Burp extension it routes all traffic through Burp's own engine, giving you full Proxy/Repeater visibility on every probe request.

---

## Installation

**Requirements:** Python 3.8+, Kali Linux (or any Linux), optionally Burp Suite Community/Pro.

```bash
git clone https://github.com/yourhandle/specter.git
cd specter
pip install -r requirements.txt
```

`requirements.txt` is intentionally minimal — only `requests` is required for standalone mode.

---

## Quick Start

### Standalone (terminal)

```bash
# Full scan, all phases, through Burp proxy
python -m core.engine \
  --target https://api.target.com \
  --login-endpoint /api/auth/login \
  --login-body '{"username":"admin","password":"admin"}' \
  --login-token-field token \
  --protected-endpoint /api/me \
  --proxy

# Auth + session only
python -m core.engine \
  --target https://target.com \
  --phases auth session \
  --verbose

# Business logic checks with cart/checkout
python -m core.engine \
  --target https://shop.target.com \
  --phases logic \
  --add-to-cart-endpoint /cart/add \
  --add-to-cart-body '{"product_id":"1","quantity":1,"price":9.99}' \
  --checkout-endpoint /checkout \
  --profile-endpoint /api/user/profile
```

Reports are written to `./reports/` by default — one `specter_report.json` and one `specter_report.html`.

### Programmatic API

```python
from core.engine import SpecterEngine, ScanConfig
from core.logic_tester import WorkflowStep

config = ScanConfig(
    target_url         = "https://api.target.com",
    login_endpoint     = "/api/login",
    login_body         = '{"username":"admin","password":"admin"}',
    login_token_field  = "token",
    protected_endpoint = "/api/me",
    logout_endpoint    = "/api/logout",
    use_proxy          = True,
    phases             = ["auth", "session"],
)

engine = SpecterEngine(config)

# Optionally inject multi-step workflow for logic checks
engine.set_workflow([
    WorkflowStep("POST", "/order/step1-address",  '{"address": "123 St"}'),
    WorkflowStep("POST", "/order/step2-payment",  '{"card": "tok_visa"}'),
    WorkflowStep("POST", "/order/step3-confirm",  '{}'),
])

findings = engine.run()
print(f"{len(findings)} findings")
```

### Burp Suite Extension

1. Open Burp Suite → **Extender → Extensions → Add**
2. Extension type: **Python**
3. Select `burp_extension/authlogic_burp.py`
4. A **Specter** tab appears in Burp's main tab bar

All scan traffic is routed through Burp's engine — every probe appears in **Proxy history** and can be sent to **Repeater** for manual follow-up.

---

## Output

### Terminal summary
```
  CRITICAL  ████  3
  HIGH      ██    2
  MEDIUM    █     1
```

### JSON report (`specter_report.json`)
```json
{
  "meta":    { "scanner": "Wraith", "version": "1.0.0", "target_url": "...", "timestamp": "..." },
  "summary": { "by_severity": { "critical": 3, "high": 2 }, "risk_score": 29 },
  "findings": [
    {
      "id": "a1b2c3d4",
      "title": "JWT None-Algorithm Bypass",
      "severity": "critical",
      "category": "authentication",
      "phase": "auth",
      "cwe": 347,
      "description": "...",
      "evidence": { "forged_token": "eyJ...", "response_status": 200 },
      "remediation": "..."
    }
  ]
}
```

### HTML report
Self-contained single file — dark terminal aesthetic, collapsible finding cards, severity donut chart, filterable by phase and severity. No CDN, no external dependencies.

---

## Detection Coverage

### Authentication (Phase 2)
| Check | Description | CWE |
|-------|-------------|-----|
| JWT none-algorithm | Forge a token with `"alg":"none"` and empty signature | CWE-347 |
| Algorithm confusion | Reuse RS256 public key as HS256 HMAC secret | CWE-327 |
| Weak JWT secret | Dictionary + common-secret brute force against HS* tokens | CWE-521 |
| Token entropy | Shannon entropy analysis flags low-randomness session tokens | CWE-330 |
| Password reset reuse | Submit the same reset token twice; check if second use succeeds | CWE-640 |
| Response-based bypass | Flip `"success":false` → `true` / status 401 → 200 in intercepted response | CWE-287 |

### Business Logic (Phase 3)
| Check | Description |
|-------|-------------|
| Negative price/qty | Send `quantity: -1` or `price: -99.99` in cart/checkout |
| Role parameter injection | Inject `"role":"admin"` into profile update or registration body |
| Workflow step skipping | Access step N+2 without completing step N |
| Coupon stacking | Apply the same coupon code multiple times in a single session |

### Session Management (Phase 4)
| Check | Description | CWE |
|-------|-------------|-----|
| Post-logout token reuse | Call a protected endpoint with the pre-logout token | CWE-613 |
| Session fixation | Supply a known session ID before login; check if server adopts it | CWE-384 |
| Concurrent sessions | Open multiple sessions; verify no policy limits them | CWE-613 |
| No invalidation on pw change | Old token still works after a password change | CWE-613 |

---

## Design Decisions

**Why Python, not Java?**  
The Burp extension uses Jython (Python 2.7 on the JVM) which lets the core scanner logic be shared between the standalone CLI and the Burp UI with minimal adaptation — no separate Java codebase to maintain.

**Why not an existing scanner?**  
Burp's active scanner: Wraith's checks are handwritten around specific vulnerability patterns that require understanding expected application flow, not signatures.

**Minimal dependencies by design.**  
Only `requests` for standalone mode. The token analyzer, entropy calculations, and JWT manipulation are implemented from scratch — no PyJWT, no cryptography library. This means it runs anywhere Python runs, including Jython.

---

## Extending Specter

Add a new check to any phase by following the pattern:

```python
# In core/auth_tester.py (or logic_tester.py / session_analyzer.py)
def _check_my_new_attack(self) -> None:
    req = HttpRequest(method="POST", url=self._url("/api/endpoint"), body="...")
    resp = self._session.send(req)

    if resp.status_code == 200 and resp.contains("admin"):
        self._add_finding(
            title       = "My New Finding",
            severity    = Severity.HIGH,
            description = "...",
            evidence    = {"status": resp.status_code, "snippet": resp.body[:200]},
            cwe         = 285,
            remediation = "...",
        )

# Then add it to run_all():
def run_all(self) -> List[ScanFinding]:
    ...
    self._check_my_new_attack()
    return self.findings
```

---

## CLI Reference

```
python -m core.engine --help

required:
  --target URL                  Base URL of the target

auth / session endpoints:
  --login-endpoint PATH         (default: /login)
  --login-body JSON
  --login-token-field KEY       JSON path or "cookie:<name>"
  --protected-endpoint PATH     Returns 200 when authenticated
  --reset-endpoint PATH
  --reset-confirm-endpoint PATH
  --reset-test-email EMAIL
  --logout-endpoint PATH
  --change-pw-endpoint PATH
  --change-pw-body JSON

business logic endpoints:
  --add-to-cart-endpoint PATH
  --add-to-cart-body JSON
  --checkout-endpoint PATH
  --profile-endpoint PATH
  --role-field FIELD            (default: role)
  --privileged-role VALUE       (default: admin)
  --coupon-endpoint PATH
  --coupon-code CODE
  --auth-header NAME:VALUE      Repeatable

scan control:
  --phases PHASE [PHASE ...]    auth logic session (default: all)
  --scan-name NAME
  --output-dir DIR              (default: ./reports)
  --no-report                   Skip writing files

HTTP / proxy:
  --proxy                       Route through Burp on 127.0.0.1:8080
  --proxy-url URL               (default: http://127.0.0.1:8080)
  --timeout SECS                (default: 15)

  --verbose / -v
```

---

## Project Status

| Phase | Module | Status |
|-------|--------|--------|
| 1 | `utils/http_client.py`, `utils/token_analyzer.py` | ✅ Complete |
| 2 | `core/auth_tester.py` | ✅ Complete |
| 3 | `core/logic_tester.py` | ✅ Complete |
| 4 | `core/session_analyzer.py` | ✅ Complete |
| 5 | `core/reporter.py` | ✅ Complete |
| 6 | `burp_extension/authlogic_burp.py` | ✅ Complete |
| — | `core/engine.py` (orchestrator + CLI) | ✅ Complete |

---

## License

MIT