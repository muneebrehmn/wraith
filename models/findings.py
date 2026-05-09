"""
models/findings.py
Wraith – Shared finding model used by all scanner phases
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from enum import Enum


class Severity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"

    @property
    def score(self) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}[self.value]


class Category(Enum):
    AUTH           = "authentication"
    BUSINESS_LOGIC = "business_logic"
    SESSION        = "session"
    TOKEN          = "token"
    INJECTION      = "injection"
    MISC           = "miscellaneous"


@dataclass
class ScanFinding:
    """
    Top-level finding emitted by any Wraith phase.
    Carries enough context for the reporter to build both JSON and HTML output.
    """
    id:          str          = field(default_factory=lambda: str(uuid.uuid4())[:12])
    title:       str          = ""
    severity:    Severity     = Severity.INFO
    category:    Category     = Category.MISC
    description: str          = ""
    evidence:    Dict[str, Any] = field(default_factory=dict)
    request:     Optional[Any] = None    # HttpRequest reference
    response:    Optional[Any] = None    # HttpResponse reference
    cwe:         Optional[int] = None
    remediation: str          = ""
    phase:       str          = ""       # "auth", "logic", "session"
    tags:        List[str]    = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id":          self.id,
            "title":       self.title,
            "severity":    self.severity.value,
            "category":    self.category.value,
            "description": self.description,
            "evidence":    self.evidence,
            "cwe":         self.cwe,
            "remediation": self.remediation,
            "phase":       self.phase,
            "tags":        self.tags,
        }