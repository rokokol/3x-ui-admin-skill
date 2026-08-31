"""HTTP client for the 3x-ui panel API.

Two panel behaviours shape this module. An unauthenticated request answers 404
rather than 401 unless it announces itself as XHR, so the header is always sent
and a 404 on a known-good path is reported as an authentication failure. And a
request to a path the panel does not serve returns an empty body with a success
status, so an empty body is an error here rather than an empty result.
"""

from __future__ import annotations

import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from .config import PanelConfig

USER_AGENT = "3x-ui-admin-skill"
TIMEOUT = 30


class ApiError(Exception):
    """A request the panel refused, or answered in a way we cannot trust."""


class AuthError(ApiError):
    """The token was rejected, or is not permitted on this endpoint."""


class Client:
    def __init__(self, config: PanelConfig):
        self.config = config
        if config.verify_tls:
            self._ssl_context = ssl.create_default_context()
        else:
            self._ssl_context = ssl._create_unverified_context()

    def _request(
        self, method: str, path: str, body: Any = None, form: dict | None = None
    ) -> Any:
        url = f"{self.config.api_base}/{path.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {self.config.token}",
            # Chooses 401 over 404 when the token is bad, which is the
            # difference between a diagnosable failure and a confusing one.
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json",
            "User-Agent": USER_AGENT,
        }

        data = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        elif body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"

        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(
                request, timeout=TIMEOUT, context=self._ssl_context
            ) as response:
                raw = response.read()
                status = response.status
        except urllib.error.HTTPError as error:
            raw = error.read()
            status = error.code
        except urllib.error.URLError as error:
            raise ApiError(f"cannot reach {url}: {error.reason}") from error

        if status in (401, 403):
            raise AuthError(
                f"{method} {path}: panel refused the token (HTTP {status}). "
                "Check the token's scope and expiry."
            )
        if status == 404 and not raw:
            raise AuthError(
                f"{method} {path}: HTTP 404 with no body. Either the base path in "
                "the URL is wrong, or the token was not accepted."
            )
        if status >= 400:
            raise ApiError(f"{method} {path}: HTTP {status}: {raw[:400].decode(errors='replace')}")
        if not raw:
            raise ApiError(
                f"{method} {path}: empty body with HTTP {status}. The panel answers "
                "this way for a path it does not serve, so nothing was done."
            )

        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ApiError(
                f"{method} {path}: response is not JSON: {raw[:200].decode(errors='replace')}"
            ) from error

        if isinstance(payload, dict) and "success" in payload:
            if not payload.get("success"):
                raise ApiError(f"{method} {path}: {payload.get('msg') or 'refused'}")
            return payload.get("obj")
        return payload

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, body: Any = None, form: dict | None = None) -> Any:
        return self._request("POST", path, body=body, form=form)

    def download(self, path: str) -> bytes:
        """Fetch a non-JSON payload, such as the database export."""
        url = f"{self.config.api_base}/{path.lstrip('/')}"
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.config.token}",
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        try:
            with urllib.request.urlopen(
                request, timeout=TIMEOUT * 4, context=self._ssl_context
            ) as response:
                return response.read()
        except urllib.error.HTTPError as error:
            raise ApiError(f"GET {path}: HTTP {error.code}") from error
        except urllib.error.URLError as error:
            raise ApiError(f"cannot reach {url}: {error.reason}") from error
