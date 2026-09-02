"""HTTP client for the 3x-ui panel API.

Two panel behaviours shape this module. An unauthenticated request answers 404
rather than 401 unless it announces itself as XHR, so the header is always sent
and a 404 on a known-good path is reported as an authentication failure. And a
request to a path the panel does not serve returns an empty body with a success
status, so an empty body is an error here rather than an empty result.

Two client behaviours are deliberate too. Redirects are never followed: urllib
would copy the Authorization header onto the new request, whatever host or
scheme it named. And a certificate pin, when configured, is checked on every
connection before a byte of the request leaves.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import PanelConfig

USER_AGENT = "3x-ui-admin-skill"
TIMEOUT = 30

_URL_WITH_PATH = re.compile(r"(https?://[^/\s'\"]+)/[^\s'\"]*")


def strip_paths(text: str) -> str:
    """Drop the path from every URL in a message; the path is the base path."""
    return _URL_WITH_PATH.sub(r"\1/…", text)


class ApiError(Exception):
    """A request the panel refused, or answered in a way we cannot trust."""


class AuthError(ApiError):
    """The token was rejected, or is not permitted on this endpoint."""


class PinError(ApiError):
    """The peer presented a certificate other than the pinned one."""


def fingerprint(der: bytes) -> str:
    return hashlib.sha256(der).hexdigest()


class _PinnedConnection(http.client.HTTPSConnection):
    pin: str | None = None

    def connect(self) -> None:
        super().connect()
        if not self.pin:
            return
        der = self.sock.getpeercert(binary_form=True)  # type: ignore[union-attr]
        seen = fingerprint(der or b"")
        if seen != self.pin:
            self.close()
            raise PinError(
                f"{self.host}:{self.port} presented certificate sha256 {seen}, "
                f"pinned {self.pin}. Either the certificate changed or this is "
                "not the panel."
            )


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, context: ssl.SSLContext, pin: str | None):
        super().__init__(context=context)
        self._ssl_context = context
        self._pin = pin

    def https_open(self, req):
        def connection(host, **kwargs):
            conn = _PinnedConnection(host, **kwargs)
            conn.pin = self._pin
            return conn

        return self.do_open(connection, req, context=self._ssl_context)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)


def path(*segments: Any) -> str:
    """Join path segments, escaping each one whole.

    A client's label goes into the path, and the panel accepts labels with `?`
    and `#` in them. Unescaped, those split the URL and address a different
    resource, or none.
    """
    return "/".join(urllib.parse.quote(str(s), safe="") for s in segments)


class Client:
    def __init__(self, config: PanelConfig):
        self.config = config
        if config.verify_tls:
            context = ssl.create_default_context()
        else:
            context = ssl._create_unverified_context()
        self._opener = urllib.request.build_opener(
            _PinnedHTTPSHandler(context, config.pin_sha256), _NoRedirect()
        )

    def _url(self, path_: str, query: dict | None = None) -> str:
        url = f"{self.config.api_base}/{path_.lstrip('/')}"
        if query:
            url += "?" + urllib.parse.urlencode(query)
        return url

    def _headers(self, accept: str = "application/json") -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self.config.token}",
            # Chooses 401 over 404 when the token is bad, which is the
            # difference between a diagnosable failure and a confusing one.
            "X-Requested-With": "XMLHttpRequest",
            "Accept": accept,
            "User-Agent": USER_AGENT,
        }

    def _open(self, request: urllib.request.Request, timeout: float) -> tuple[int, bytes]:
        try:
            with self._opener.open(request, timeout=timeout) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            if 300 <= error.code < 400:
                target = strip_paths(error.headers.get("Location") or "?")
                raise ApiError(
                    f"{request.get_method()} {self._short(request)}: the panel "
                    f"redirected (HTTP {error.code}) to {target}; not followed, the "
                    "token would have gone with it. Check the URL and base path."
                ) from error
            return error.code, error.read()
        except PinError:
            raise
        except urllib.error.URLError as error:
            reason = error.reason
            if isinstance(reason, PinError):
                raise reason from error
            raise ApiError(
                f"cannot reach {self.config.display_url}: {strip_paths(str(reason))}"
            ) from error
        except (http.client.HTTPException, OSError) as error:
            raise ApiError(
                f"cannot reach {self.config.display_url}: {strip_paths(str(error))}"
            ) from error

    def _short(self, request: urllib.request.Request) -> str:
        full = request.full_url
        base = self.config.api_base + "/"
        return full[len(base):] if full.startswith(base) else strip_paths(full)

    def _request(
        self,
        method: str,
        path_: str,
        body: Any = None,
        form: dict | None = None,
        query: dict | None = None,
    ) -> Any:
        headers = self._headers()
        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(
            self._url(path_, query), data=data, headers=headers, method=method
        )
        status, raw = self._open(request, TIMEOUT)
        shown = self._short(request)

        if status in (401, 403):
            raise AuthError(
                f"{method} {shown}: panel refused the token (HTTP {status}). "
                "Check the token's scope and expiry."
            )
        if status == 404 and not raw:
            raise AuthError(
                f"{method} {shown}: HTTP 404 with no body. Either the base path in "
                "the URL is wrong, or the token was not accepted."
            )
        if status >= 400:
            raise ApiError(f"{method} {shown}: HTTP {status}: {raw[:400].decode(errors='replace')}")
        if not raw:
            raise ApiError(
                f"{method} {shown}: empty body with HTTP {status}. The panel answers "
                "this way for a path it does not serve, so nothing was done."
            )

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ApiError(
                f"{method} {shown}: response is not JSON: {raw[:200].decode(errors='replace')}"
            ) from error

        if isinstance(payload, dict) and "success" in payload:
            if not payload.get("success"):
                raise ApiError(f"{method} {shown}: {payload.get('msg') or 'refused'}")
            return payload.get("obj")
        return payload

    def get(self, path_: str, query: dict | None = None) -> Any:
        return self._request("GET", path_, query=query)

    def post(
        self, path_: str, body: Any = None, form: dict | None = None, query: dict | None = None
    ) -> Any:
        return self._request("POST", path_, body=body, form=form, query=query)

    def download(self, path_: str) -> bytes:
        """Fetch a non-JSON payload, such as the database export."""
        request = urllib.request.Request(
            self._url(path_), headers=self._headers(accept="*/*"), method="GET"
        )
        status, raw = self._open(request, TIMEOUT * 4)
        if status in (401, 403):
            raise AuthError(f"GET {path_}: panel refused the token (HTTP {status})")
        if status >= 400:
            raise ApiError(f"GET {path_}: HTTP {status}")
        if not raw:
            raise ApiError(f"GET {path_}: empty body with HTTP {status}")
        return raw
