"""
utils/http_client.py
Wraith – HTTP Client Foundation
Dual-mode: standalone (requests) + Burp-passthrough shim
"""

from __future__ import annotations

import time
import uuid
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

class AuthType(Enum):
    NONE      = "none"
    BEARER    = "bearer"
    BASIC     = "basic"
    COOKIE    = "cookie"
    CUSTOM    = "custom"


@dataclass
class HttpRequest:
    method:  str
    url:     str
    headers: Dict[str, str]          = field(default_factory=dict)
    body:    Optional[str]           = None
    params:  Dict[str, str]          = field(default_factory=dict)
    auth_type: AuthType              = AuthType.NONE
    tag:     str                     = field(default_factory=lambda: str(uuid.uuid4())[:8])
    metadata: Dict[str, Any]         = field(default_factory=dict)   # arbitrary probe context

    @property
    def parsed_url(self) -> urllib.parse.ParseResult:
        return urllib.parse.urlparse(self.url)

    @property
    def host(self) -> str:
        return self.parsed_url.netloc

    def clone(self, **overrides) -> "HttpRequest":
        import copy
        c = copy.deepcopy(self)
        for k, v in overrides.items():
            setattr(c, k, v)
        c.tag = str(uuid.uuid4())[:8]
        return c


@dataclass
class HttpResponse:
    status_code: int
    headers:     Dict[str, str]
    body:        str
    elapsed_ms:  float
    request:     HttpRequest
    redirects:   List[Tuple[int, str]] = field(default_factory=list)
    error:       Optional[str]         = None

    # ---- convenience helpers -----------------------------------------------

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").lower()

    @property
    def is_json(self) -> bool:
        return "application/json" in self.content_type

    def json(self) -> Any:
        return json.loads(self.body)

    def header(self, name: str) -> Optional[str]:
        """Case-insensitive header lookup."""
        name_lower = name.lower()
        for k, v in self.headers.items():
            if k.lower() == name_lower:
                return v
        return None

    def contains(self, *substrings: str, case_sensitive: bool = False) -> bool:
        body = self.body if case_sensitive else self.body.lower()
        return any((s if case_sensitive else s.lower()) in body for s in substrings)

    def __repr__(self) -> str:
        return f"<HttpResponse {self.status_code} [{self.elapsed_ms:.0f}ms] req={self.request.tag}>"


# ---------------------------------------------------------------------------
# Session – the actual HTTP driver
# ---------------------------------------------------------------------------

class SpecterSession:
    """
    Thin wrapper around `requests.Session`.
    Burp integration: pass a `burp_callbacks` object (from Jython) and all
    traffic will be routed through Burp's makeHttpRequest instead.
    """

    DEFAULT_TIMEOUT  = 15          # seconds
    DEFAULT_UA       = (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0 Safari/537.36 Wraith/1.0"
    )

    def __init__(
        self,
        proxy: Optional[str]         = None,
        verify_ssl: bool             = False,
        follow_redirects: bool       = True,
        timeout: int                 = DEFAULT_TIMEOUT,
        default_headers: Optional[Dict[str, str]] = None,
        burp_callbacks: Any          = None,   # IBurpExtenderCallbacks (Jython)
    ):
        self.proxy             = proxy or {}
        self.verify_ssl        = verify_ssl
        self.follow_redirects  = follow_redirects
        self.timeout           = timeout
        self.burp_callbacks    = burp_callbacks
        self._history: List[HttpResponse] = []

        self._base_headers: Dict[str, str] = {
            "User-Agent": self.DEFAULT_UA,
            "Accept": "*/*",
        }
        if default_headers:
            self._base_headers.update(default_headers)

        # Lazy-import so Jython environments (no requests) don't explode
        self._session = None
        if burp_callbacks is None:
            self._init_requests_session()

    # ---- internal setup ----------------------------------------------------

    def _init_requests_session(self):
        try:
            import requests
            from requests.packages.urllib3.exceptions import InsecureRequestWarning
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

            self._session = requests.Session()
            self._session.verify  = self.verify_ssl
            self._session.headers.update(self._base_headers)

            if self.proxy:
                proxy_url = self.proxy if isinstance(self.proxy, str) else None
                if proxy_url:
                    self._session.proxies = {
                        "http":  proxy_url,
                        "https": proxy_url,
                    }
        except ImportError:
            raise RuntimeError(
                "requests library not found. "
                "Install with: pip install requests"
            )

    # ---- public API --------------------------------------------------------

    def send(self, req: HttpRequest) -> HttpResponse:
        """Dispatch a request; routes to Burp or requests automatically."""
        if self.burp_callbacks is not None:
            return self._send_via_burp(req)
        return self._send_via_requests(req)

    def get(self, url: str, **kwargs) -> HttpResponse:
        return self.send(HttpRequest(method="GET", url=url, **kwargs))

    def post(self, url: str, body: str = "", **kwargs) -> HttpResponse:
        return self.send(HttpRequest(method="POST", url=url, body=body, **kwargs))

    def set_bearer(self, token: str):
        self._base_headers["Authorization"] = f"Bearer {token}"
        if self._session:
            self._session.headers["Authorization"] = f"Bearer {token}"

    def set_cookie(self, name: str, value: str):
        current = self._base_headers.get("Cookie", "")
        pair = f"{name}={value}"
        self._base_headers["Cookie"] = (current + "; " + pair).lstrip("; ")
        if self._session:
            self._session.headers["Cookie"] = self._base_headers["Cookie"]

    def clear_auth(self):
        for h in ("Authorization", "Cookie"):
            self._base_headers.pop(h, None)
            if self._session:
                self._session.headers.pop(h, None)

    @property
    def history(self) -> List[HttpResponse]:
        return list(self._history)

    def clear_history(self):
        self._history.clear()

    # ---- requests backend --------------------------------------------------

    def _send_via_requests(self, req: HttpRequest) -> HttpResponse:
        import requests as rq

        merged_headers = {**self._base_headers, **req.headers}
        t0 = time.perf_counter()
        redirects: List[Tuple[int, str]] = []
        error: Optional[str] = None
        raw: Optional[rq.Response] = None

        try:
            raw = self._session.request(
                method        = req.method.upper(),
                url           = req.url,
                headers       = merged_headers,
                data          = req.body,
                params        = req.params or None,
                timeout       = self.timeout,
                allow_redirects = self.follow_redirects,
            )
            for r in raw.history:
                redirects.append((r.status_code, r.headers.get("Location", "")))

        except rq.exceptions.Timeout:
            error = "timeout"
        except rq.exceptions.ConnectionError as e:
            error = f"connection_error: {e}"
        except Exception as e:
            error = f"unexpected: {e}"

        elapsed = (time.perf_counter() - t0) * 1000

        if error or raw is None:
            resp = HttpResponse(
                status_code=0,
                headers={},
                body="",
                elapsed_ms=elapsed,
                request=req,
                error=error,
            )
        else:
            resp = HttpResponse(
                status_code=raw.status_code,
                headers=dict(raw.headers),
                body=raw.text,
                elapsed_ms=elapsed,
                request=req,
                redirects=redirects,
            )

        self._history.append(resp)
        return resp

    # ---- Burp backend (Jython) ---------------------------------------------

    def _send_via_burp(self, req: HttpRequest) -> HttpResponse:
        """
        Routes through Burp's IExtensionHelpers / makeHttpRequest.
        Called only when self.burp_callbacks is set (Jython context).
        """
        from burp_extension._burp_shim import burp_send   # loaded in Jython env
        return burp_send(req, self.burp_callbacks, self._base_headers)


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------

def make_session(
    proxy: str = "http://127.0.0.1:8080",
    use_proxy: bool = False,
    **kwargs,
) -> SpecterSession:
    """
    Quick factory. use_proxy=True routes through Burp (default port).
    """
    # verify_ssl defaults False (pentest tool — self-signed certs are expected).
    # Callers can override via kwargs without causing a duplicate-keyword error.
    kwargs.setdefault("verify_ssl", False)
    return SpecterSession(
        proxy = proxy if use_proxy else None,
        **kwargs,
    )