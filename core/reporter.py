"""
wraith/core/reporter.py
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Phase 5 – Reporter

Consumes a list of ScanFinding objects and produces:
  1. Structured JSON report  →  wraith_report.json
  2. Standalone HTML report  →  wraith_report.html  (no external dependencies)

JSON schema:
  {
    "meta":     { scan metadata, target, timestamp, counts },
    "summary":  { severity breakdown dict },
    "findings": [ ... ScanFinding.to_dict() ... ]
  }

HTML report:
  - Self-contained single file (inline CSS + JS, no CDN)
  - Dark terminal aesthetic: monospace, neon severity badges
  - Collapsible finding cards with evidence/remediation sections
  - Summary donut chart drawn with pure SVG
  - Filterable by severity and phase

Usage:
    from core.reporter import Reporter
    from models.findings import ScanFinding

    findings = [...]   # collected from all phases

    r = Reporter(
        findings    = findings,
        target_url  = "https://target.com",
        scan_name   = "Wraith Auth Scan",
        output_dir  = "./reports",
    )

    json_path = r.write_json()
    html_path = r.write_html()
    print(r.summary_text())   # quick terminal summary
"""

from __future__ import annotations

import json
import os
import datetime
from collections import Counter
from typing import Any, Dict, List, Optional

from models.findings import ScanFinding, Severity, Category


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Severity display config — used in both JSON meta and HTML rendering
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

# Neon accent colors matching the terminal dark theme
SEVERITY_COLORS = {
    Severity.CRITICAL: "#ff2d55",   # neon red
    Severity.HIGH:     "#ff9500",   # amber
    Severity.MEDIUM:   "#ffd60a",   # yellow
    Severity.LOW:      "#30d158",   # green
    Severity.INFO:     "#636366",   # muted grey
}

SEVERITY_ICONS = {
    Severity.CRITICAL: "☠",
    Severity.HIGH:     "⚠",
    Severity.MEDIUM:   "◆",
    Severity.LOW:      "◇",
    Severity.INFO:     "·",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Reporter
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class Reporter:
    """
    Takes aggregated findings from all phases and renders them into
    structured JSON and a polished standalone HTML report.
    """

    def __init__(
        self,
        findings:   List[ScanFinding],
        target_url: str  = "",
        scan_name: str  = "Wraith Security Scan",
        output_dir: str  = ".",
        scanner_version: str = "1.0.0",
    ):
        self.findings        = findings
        self.target_url      = target_url
        self.scan_name       = scan_name
        self.output_dir      = output_dir
        self.scanner_version = scanner_version
        self.timestamp       = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00","Z")

        # Pre-compute counts once — used by both renderers
        self._counts: Dict[str, int] = {
            sev.value: sum(1 for f in findings if f.severity == sev)
            for sev in SEVERITY_ORDER
        }

        # Sort findings by severity score descending (critical first)
        self._sorted = sorted(
            findings,
            key=lambda f: f.severity.score,
            reverse=True,
        )

        os.makedirs(output_dir, exist_ok=True)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # JSON output
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def write_json(self, filename: str = "wraith_report.json") -> str:
        """
        Writes the full report as structured JSON.
        Returns the absolute path to the created file.
        """
        path = os.path.join(self.output_dir, filename)

        report = {
            # ── Scan metadata ──────────────────────────────────────────────
            "meta": {
                "scanner":         "Wraith",
                "version":         self.scanner_version,
                "scan_name":       self.scan_name,
                "target_url":      self.target_url,
                "timestamp":       self.timestamp,
                "total_findings":  len(self.findings),
            },
            # ── Severity breakdown ─────────────────────────────────────────
            "summary": {
                "by_severity": self._counts,
                "by_phase":    self._counts_by("phase"),
                "by_category": self._counts_by("category"),
                # Risk score: weighted sum (critical=5, high=4 ...)
                "risk_score":  sum(f.severity.score for f in self.findings),
            },
            # ── Individual findings (sorted by severity) ───────────────────
            "findings": [self._finding_to_dict(f) for f in self._sorted],
        }

        with open(path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, default=str)

        print(f"[+] JSON report → {path}")
        return path

    def _finding_to_dict(self, f: ScanFinding) -> Dict[str, Any]:
        """
        Serialises a ScanFinding, including condensed request/response info.
        Avoids embedding full response bodies (can be huge) — truncates to 500 chars.
        """
        d = f.to_dict()

        # Add request details if available
        if f.request:
            d["request"] = {
                "method":  getattr(f.request, "method", ""),
                "url":     getattr(f.request, "url",    ""),
                "headers": self._safe_dict(getattr(f.request, "headers", {})),
                "body":    str(getattr(f.request, "body", "") or "")[:500],
            }

        # Add response details if available
        if f.response:
            d["response"] = {
                "status":  getattr(f.response, "status_code", 0),
                "headers": self._safe_dict(getattr(f.response, "headers", {})),
                "body":    str(getattr(f.response, "body", "") or "")[:500],
            }

        # CWE link for easy reference
        if f.cwe:
            d["cwe_url"] = f"https://cwe.mitre.org/data/definitions/{f.cwe}.html"

        return d

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # HTML output
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def write_html(self, filename: str = "wraith_report.html") -> str:
        """
        Writes a self-contained HTML report.
        Returns the absolute path to the created file.
        """
        path = os.path.join(self.output_dir, filename)

        html = (
            self._html_head()
            + self._html_header()
            + self._html_summary_bar()
            + self._html_filters()
            + self._html_findings()
            + self._html_footer()
        )

        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)

        print(f"[+] HTML report → {path}")
        return path

    # ── HTML section builders ────────────────────────────────────────────────


    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # HTML generation — each method returns a clean HTML string.
    # Uses triple-quoted strings throughout — no concatenation hacks.
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _html_head(self) -> str:
        """
        Full <head> block with inline CSS.
        Fully self-contained — no external resources, no CDN.
        Uses system monospace/sans-serif stack for zero-dependency rendering.
        """
        title = self._esc(self.scan_name)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Wraith &mdash; {title}</title>
  <style>

    /* ── Reset ─────────────────────────────────────── */
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --black:   #080808;
      --surface: #0f0f0f;
      --edge:    #1a1a1a;
      --mid:     #2a2a2a;
      --text:    #c8c8c8;
      --dim:     #555555;
      --white:   #f0f0f0;

      --mono:    'Cascadia Code', 'Fira Code', 'Consolas', 'Menlo', monospace;
      --sans:    -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      --display: 'Courier New', 'Courier', monospace;

      --crit: #c0392b;
      --high: #b8621a;
      --med:  #9a7d0a;
      --low:  #1e8449;
      --info: #3a3a3a;
    }}

    html {{ scroll-behavior: smooth; }}

    body {{
      background: var(--black);
      color: var(--text);
      font-family: var(--sans);
      font-size: 14px;
      font-weight: 300;
      line-height: 1.7;
      -webkit-font-smoothing: antialiased;
    }}

    a {{ color: var(--text); text-decoration: none; }}
    a:hover {{ color: var(--white); }}

    code {{
      font-family: var(--mono);
      font-size: 12px;
      background: var(--surface);
      border: 1px solid var(--edge);
      border-radius: 2px;
      padding: 1px 6px;
      color: #888;
    }}

    pre {{
      font-family: var(--mono);
      font-size: 11.5px;
      background: var(--surface);
      border: 1px solid var(--edge);
      padding: 14px 18px;
      overflow-x: auto;
      line-height: 1.65;
      color: #555;
      white-space: pre-wrap;
      word-break: break-all;
    }}

    /* ── Layout ────────────────────────────────────── */
    .wrap {{
      max-width: 1000px;
      margin: 0 auto;
      padding: 0 40px;
    }}

    /* ── Top accent bar ────────────────────────────── */
    .topbar {{
      height: 2px;
      background: var(--mid);
    }}

    /* ── Header ────────────────────────────────────── */
    .rpt-header {{
      padding: 40px 0 32px;
      border-bottom: 1px solid var(--edge);
      margin-bottom: 36px;
    }}

    .rpt-header-inner {{
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      gap: 24px;
      flex-wrap: wrap;
    }}

    .rpt-brand {{
      font-family: var(--display);
      font-size: 20px;
      letter-spacing: 0.12em;
      color: var(--white);
    }}

    .rpt-brand .sub {{
      font-family: var(--mono);
      font-size: 11px;
      color: var(--dim);
      letter-spacing: 0.15em;
      text-transform: uppercase;
      vertical-align: middle;
      margin-left: 10px;
      font-weight: 300;
    }}

    .rpt-scanname {{
      font-family: var(--mono);
      font-size: 11px;
      color: var(--dim);
      margin-top: 6px;
      letter-spacing: 0.06em;
    }}

    .rpt-meta {{
      text-align: right;
      font-family: var(--mono);
      font-size: 11px;
      color: var(--dim);
      line-height: 2;
      letter-spacing: 0.04em;
    }}

    .rpt-meta strong {{
      color: var(--text);
      font-weight: 400;
    }}

    /* ── Summary row ───────────────────────────────── */
    .summary-row {{
      display: flex;
      gap: 1px;
      background: var(--edge);
      border: 1px solid var(--edge);
      margin-bottom: 32px;
    }}

    .sev-cell {{
      flex: 1;
      background: var(--black);
      padding: 20px 24px;
      cursor: pointer;
      transition: background 0.15s;
    }}

    .sev-cell:hover {{ background: var(--surface); }}

    .sev-cell .num {{
      font-family: var(--display);
      font-size: 32px;
      letter-spacing: 0.04em;
      line-height: 1;
    }}

    .sev-cell .lbl {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--dim);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin-top: 4px;
    }}

    /* ── Filters ───────────────────────────────────── */
    .filter-row {{
      display: flex;
      gap: 6px;
      margin-bottom: 20px;
      flex-wrap: wrap;
      align-items: center;
    }}

    .filter-label {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--dim);
      text-transform: uppercase;
      letter-spacing: 0.12em;
      margin-right: 4px;
    }}

    .filter-btn {{
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      background: transparent;
      border: 1px solid var(--edge);
      color: var(--dim);
      padding: 4px 12px;
      cursor: pointer;
      transition: border-color 0.15s, color 0.15s;
    }}

    .filter-btn:hover {{
      border-color: var(--mid);
      color: var(--text);
    }}

    .filter-btn.active {{
      border-color: var(--text);
      color: var(--white);
      background: var(--surface);
    }}

    /* ── Count label ───────────────────────────────── */
    .count-label {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--dim);
      letter-spacing: 0.1em;
      text-transform: uppercase;
      margin-bottom: 12px;
    }}

    /* ── Findings list ─────────────────────────────── */
    .findings-list {{
      display: flex;
      flex-direction: column;
      gap: 1px;
      background: var(--edge);
      border: 1px solid var(--edge);
      margin-bottom: 60px;
    }}

    /* ── Finding card ──────────────────────────────── */
    .fcard {{
      background: var(--black);
      overflow: hidden;
    }}

    .fcard.hidden {{ display: none; }}

    .fcard-header {{
      display: flex;
      align-items: center;
      gap: 14px;
      padding: 16px 20px;
      cursor: pointer;
      user-select: none;
      border-left: 2px solid transparent;
      transition: background 0.15s;
    }}

    .fcard-header:hover {{ background: var(--surface); }}

    .sev-dot {{
      width: 6px;
      height: 6px;
      border-radius: 50%;
      flex-shrink: 0;
    }}

    .sev-label {{
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: var(--dim);
      flex-shrink: 0;
      min-width: 62px;
    }}

    .fcard-title {{
      font-family: var(--sans);
      font-size: 13.5px;
      font-weight: 400;
      color: var(--white);
      flex: 1;
    }}

    .fcard-phase {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--dim);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      flex-shrink: 0;
    }}

    .fcard-chevron {{
      font-size: 9px;
      color: var(--dim);
      transition: transform 0.2s;
      flex-shrink: 0;
      margin-left: 8px;
    }}

    .fcard-chevron.open {{ transform: rotate(180deg); }}

    /* Severity left-border colors */
    .bl-critical {{ border-left-color: var(--crit) !important; }}
    .bl-high     {{ border-left-color: var(--high) !important; }}
    .bl-medium   {{ border-left-color: var(--med)  !important; }}
    .bl-low      {{ border-left-color: var(--low)  !important; }}
    .bl-info     {{ border-left-color: var(--info) !important; }}

    /* Severity dot colors */
    .dot-critical {{ background: var(--crit); }}
    .dot-high     {{ background: var(--high); }}
    .dot-medium   {{ background: var(--med);  }}
    .dot-low      {{ background: var(--low);  }}
    .dot-info     {{ background: var(--info); }}

    /* ── Card body ─────────────────────────────────── */
    .fcard-body {{
      display: none;
      padding: 0 22px 24px;
      border-top: 1px solid var(--edge);
    }}

    .fcard-body.open {{ display: block; }}

    /* ── Sections inside card body ─────────────────── */
    .fsection {{
      margin-top: 20px;
    }}

    .fsection-label {{
      font-family: var(--mono);
      font-size: 10px;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      color: var(--dim);
      margin-bottom: 8px;
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .fsection-label::after {{
      content: '';
      flex: 1;
      height: 1px;
      background: var(--edge);
    }}

    .fdescription {{
      font-size: 13px;
      font-weight: 300;
      color: var(--text);
      line-height: 1.75;
    }}

    .fremediation {{
      font-family: var(--mono);
      font-size: 11.5px;
      color: #3a7d44;
      background: var(--surface);
      border: 1px solid var(--edge);
      border-left: 2px solid var(--low);
      padding: 12px 16px;
      line-height: 1.7;
    }}

    .tag-list {{
      display: flex;
      gap: 5px;
      flex-wrap: wrap;
      margin-top: 10px;
    }}

    .tag {{
      font-family: var(--mono);
      font-size: 10px;
      background: var(--surface);
      border: 1px solid var(--edge);
      color: var(--dim);
      padding: 2px 8px;
      letter-spacing: 0.06em;
    }}

    .cwe-link {{
      display: inline-flex;
      align-items: center;
      gap: 4px;
      font-family: var(--mono);
      font-size: 10px;
      color: var(--dim);
      border: 1px solid var(--edge);
      padding: 3px 9px;
      margin-top: 8px;
      letter-spacing: 0.06em;
      transition: border-color 0.15s, color 0.15s;
    }}

    .cwe-link:hover {{
      border-color: var(--mid);
      color: var(--text);
    }}

    /* ── Empty state ───────────────────────────────── */
    .empty-state {{
      text-align: center;
      padding: 80px 20px;
      font-family: var(--mono);
      font-size: 12px;
      color: var(--dim);
      letter-spacing: 0.1em;
      text-transform: uppercase;
    }}

    /* ── Footer ────────────────────────────────────── */
    .rpt-footer {{
      border-top: 1px solid var(--edge);
      padding: 28px 0;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }}

    .rpt-footer-logo {{
      font-family: var(--display);
      font-size: 16px;
      letter-spacing: 0.1em;
      color: var(--mid);
    }}

    .rpt-footer-meta {{
      font-family: var(--mono);
      font-size: 10px;
      color: var(--dim);
      letter-spacing: 0.06em;
    }}

    /* ── Responsive ────────────────────────────────── */
    @media (max-width: 640px) {{
      .wrap {{ padding: 0 20px; }}
      .summary-row {{ flex-wrap: wrap; }}
      .sev-cell {{ min-width: 80px; }}
      .rpt-header-inner {{ flex-direction: column; }}
      .rpt-meta {{ text-align: left; }}
    }}

  </style>
</head>
<body>
"""

    def _html_header(self) -> str:
        """Top header: brand name, scan name, and metadata block."""
        total  = len(self.findings)
        risk   = sum(f.severity.score for f in self.findings)
        plural = "s" if total != 1 else ""

        if   risk == 0:   risk_label = "None"
        elif risk < 5:    risk_label = "Low"
        elif risk < 15:   risk_label = "Moderate"
        elif risk < 30:   risk_label = "High"
        else:             risk_label = "Critical"

        target   = self._esc(self.target_url or "N/A")
        ts       = self._esc(self.timestamp)
        ver      = self._esc(self.scanner_version)
        scanname = self._esc(self.scan_name)

        return f"""
<div class="topbar"></div>
<div class="wrap">

  <div class="rpt-header">
    <div class="rpt-header-inner">

      <div>
        <div class="rpt-brand">
          SPECTER
          <span class="sub">Security Report</span>
        </div>
        <div class="rpt-scanname">{scanname}</div>
      </div>

      <div class="rpt-meta">
        <div><strong>{target}</strong></div>
        <div>{ts}</div>
        <div>v{ver} &nbsp;&middot;&nbsp; {total} finding{plural} &nbsp;&middot;&nbsp; Risk: {risk_label}</div>
      </div>

    </div>
  </div>

"""

    def _html_summary_bar(self) -> str:
        """
        Five severity count cells — click any to filter.
        Colors match the CSS variables defined in _html_head.
        """
        color_map = {
            "critical": "var(--crit)",
            "high":     "var(--high)",
            "medium":   "var(--med)",
            "low":      "var(--low)",
            "info":     "var(--info)",
        }

        cells = ""
        for sev in SEVERITY_ORDER:
            count = self._counts[sev.value]
            color = color_map[sev.value]
            cells += f"""
    <div class="sev-cell" onclick="filterBySev('{sev.value}')" title="Show {sev.value}">
      <div class="num" style="color: {color};">{count}</div>
      <div class="lbl">{sev.value}</div>
    </div>"""

        return f"""
  <div class="summary-row">
    {cells}
  </div>

"""

    def _html_filters(self) -> str:
        """Severity + phase filter buttons."""
        phases = sorted({f.phase for f in self.findings if f.phase})
        plural = "s" if len(self.findings) != 1 else ""

        # Severity buttons
        sev_buttons = '<button class="filter-btn active" onclick="filterBySev(\'all\')">All</button>\n'
        for sev in SEVERITY_ORDER:
            if self._counts[sev.value] > 0:
                sev_buttons += (
                    f'    <button class="filter-btn" '
                    f'onclick="filterBySev(\'{sev.value}\')">'
                    f'{sev.value}</button>\n'
                )

        # Phase buttons (only shown if findings have phases)
        phase_section = ""
        if phases:
            phase_section = '\n    <span class="filter-label">Phase</span>\n'
            for p in phases:
                phase_section += (
                    f'    <button class="filter-btn" '
                    f'onclick="filterByPhase(\'{p}\')">'
                    f'{p}</button>\n'
                )

        return f"""
  <div class="filter-row">
    <span class="filter-label">Filter</span>
    {sev_buttons}
    {phase_section}
  </div>

  <div class="count-label">{len(self.findings)} finding{plural}</div>

"""

    def _html_findings(self) -> str:
        """Renders all finding cards, sorted by severity."""
        if not self._sorted:
            return """
  <div class="empty-state">
    No findings &mdash; scan clean or no checks configured.
  </div>

"""
        cards = "\n".join(self._finding_card(f) for f in self._sorted)
        return f"""
  <div class="findings-list" id="findings-list">
{cards}
  </div>

"""

    def _finding_card(self, f: ScanFinding) -> str:
        """Renders one collapsible finding card."""
        sev     = f.severity.value
        card_id = f"card-{self._esc(f.id)}"
        phase   = f.phase.upper() if f.phase else f.category.value.upper()

        # ── CWE link ───────────────────────────────────────────────────
        cwe_html = ""
        if f.cwe:
            cwe_html = (
                f'\n        <a class="cwe-link" '
                f'href="https://cwe.mitre.org/data/definitions/{f.cwe}.html" '
                f'target="_blank">CWE-{f.cwe} &nearr;</a>'
            )

        # ── Tags ───────────────────────────────────────────────────────
        tags_html = ""
        if f.tags:
            tag_items = "".join(
                f'<span class="tag">{self._esc(t)}</span>' for t in f.tags
            )
            tags_html = f'\n        <div class="tag-list">{tag_items}</div>'

        # ── Evidence ───────────────────────────────────────────────────
        evidence_html = ""
        if f.evidence:
            ev_json = json.dumps(f.evidence, indent=2, default=str)
            evidence_html = f"""
      <div class="fsection">
        <div class="fsection-label">Evidence</div>
        <pre>{self._esc(ev_json)}</pre>
      </div>"""

        # ── Request ────────────────────────────────────────────────────
        request_html = ""
        if f.request:
            method = getattr(f.request, "method", "?")
            url    = getattr(f.request, "url",    "?")
            body   = str(getattr(f.request, "body", "") or "")[:300]
            body_line = f"\n{self._esc(body)}" if body else ""
            request_html = f"""
      <div class="fsection">
        <div class="fsection-label">Request</div>
        <pre>{self._esc(method)} {self._esc(url)}{body_line}</pre>
      </div>"""

        # ── Response ───────────────────────────────────────────────────
        response_html = ""
        if f.response:
            status = getattr(f.response, "status_code", "?")
            rbody  = str(getattr(f.response, "body", "") or "")[:400]
            response_html = f"""
      <div class="fsection">
        <div class="fsection-label">Response <code>{status}</code></div>
        <pre>{self._esc(rbody)}</pre>
      </div>"""

        # ── Remediation ────────────────────────────────────────────────
        remediation_html = ""
        if f.remediation:
            remediation_html = f"""
      <div class="fsection">
        <div class="fsection-label">Remediation</div>
        <div class="fremediation">{self._esc(f.remediation)}</div>
      </div>"""

        return f"""
    <div class="fcard" id="{card_id}" data-sev="{sev}" data-phase="{self._esc(f.phase)}">

      <div class="fcard-header bl-{sev}" onclick="toggleCard('{card_id}')">
        <span class="sev-dot dot-{sev}"></span>
        <span class="sev-label">{sev.upper()}</span>
        <span class="fcard-title">{self._esc(f.title)}</span>
        <span class="fcard-phase">{self._esc(phase)}</span>
        <span class="fcard-chevron" id="chev-{card_id}">&#9660;</span>
      </div>

      <div class="fcard-body" id="body-{card_id}">

        <div class="fsection">
          <div class="fsection-label">Description</div>
          <div class="fdescription">{self._esc(f.description)}</div>
          {cwe_html}
          {tags_html}
        </div>
        {evidence_html}
        {request_html}
        {response_html}
        {remediation_html}

      </div>

    </div>"""

    def _html_footer(self) -> str:
        """Footer block and inline JavaScript for filters and card toggles."""
        total  = len(self.findings)
        plural = "s" if total != 1 else ""
        ts     = self._esc(self.timestamp)
        ver    = self._esc(self.scanner_version)

        return f"""
  <div class="rpt-footer">
    <div class="rpt-footer-logo">SPECTER</div>
    <div class="rpt-footer-meta">
      {total} finding{plural} &nbsp;&middot;&nbsp; {ts} &nbsp;&middot;&nbsp; v{ver}
    </div>
  </div>

</div><!-- /.wrap -->

<script>

  // ── Card toggle ───────────────────────────────────────────────
  function toggleCard(id) {{
    var body = document.getElementById('body-' + id);
    var chev = document.getElementById('chev-' + id);
    body.classList.toggle('open');
    chev.classList.toggle('open');
  }}

  // ── Active filter state ───────────────────────────────────────
  var activeSev   = 'all';
  var activePhase = 'all';

  function applyFilters() {{
    var cards = document.querySelectorAll('.fcard');
    cards.forEach(function(card) {{
      var sevMatch   = activeSev   === 'all' || card.dataset.sev   === activeSev;
      var phaseMatch = activePhase === 'all' || card.dataset.phase === activePhase;
      card.classList.toggle('hidden', !(sevMatch && phaseMatch));
    }});
  }}

  function filterBySev(sev) {{
    activeSev = sev;
    document.querySelectorAll('.filter-btn').forEach(function(btn) {{
      var match = (sev === 'all' && btn.textContent.trim() === 'All')
               || btn.textContent.trim().toLowerCase() === sev.toLowerCase();
      btn.classList.toggle('active', match);
    }});
    applyFilters();
  }}

  function filterByPhase(phase) {{
    activePhase = (activePhase === phase) ? 'all' : phase;
    applyFilters();
  }}

  // ── Auto-open first critical or high finding ──────────────────
  (function() {{
    var first = document.querySelector('.fcard[data-sev="critical"]')
             || document.querySelector('.fcard[data-sev="high"]');
    if (first) {{
      toggleCard(first.id);
    }}
  }})();

</script>

</body>
</html>"""


    def summary_text(self) -> str:
        """
        Returns a compact terminal-friendly summary string.
        Suitable for piping or printing at the end of a scan run.
        """
        lines = [
            "",
            "━" * 52,
            f"  SPECTER REPORT  —  {self.scan_name}",
            "━" * 52,
            f"  Target : {self.target_url or 'N/A'}",
            f"  Time   : {self.timestamp}",
            f"  Total  : {len(self.findings)} findings",
            "",
        ]

        for sev in SEVERITY_ORDER:
            count = self._counts[sev.value]
            if count > 0:
                bar = "█" * min(count, 30)
                lines.append(f"  {sev.value.upper():<10} {bar}  ({count})")

        lines += [
            "",
            f"  Risk score : {sum(f.severity.score for f in self.findings)}",
            "━" * 52,
            "",
        ]
        return "\n".join(lines)

    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
    # Helpers
    # ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

    def _counts_by(self, attr: str) -> Dict[str, int]:
        """Count findings grouped by a string attribute (phase, category)."""
        counts: Counter = Counter()
        for f in self.findings:
            val = getattr(f, attr, None)
            key = val.value if hasattr(val, "value") else str(val or "unknown")
            counts[key] += 1
        return dict(counts)

    @staticmethod
    def _esc(text: Any) -> str:
        """HTML-escape a value for safe embedding in HTML content."""
        s = str(text) if text is not None else ""
        return (
            s.replace("&", "&amp;")
             .replace("<", "&lt;")
             .replace(">", "&gt;")
             .replace('"', "&quot;")
             .replace("'", "&#x27;")
        )

    @staticmethod
    def _safe_dict(d: Any) -> Dict[str, str]:
        """Convert a headers dict to {str: str}, dropping non-serialisable values."""
        if not isinstance(d, dict):
            return {}
        return {str(k): str(v) for k, v in d.items()}