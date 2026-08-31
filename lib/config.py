"""Where the panel is and how to authenticate to it.

Resolution order, first hit wins: explicit arguments, environment, the skill's
own secrets/ directory, then a node registry shared with an infrastructure
repository. Nothing here assumes a particular network: a panel on loopback, on
a tunnel address or on the public internet is reached the same way.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 and older
    tomllib = None

SKILL_ROOT = Path(__file__).resolve().parent.parent
SECRETS_DIR = SKILL_ROOT / "secrets"


class ConfigError(Exception):
    """Raised when the panel cannot be located or authenticated."""


@dataclass
class PanelConfig:
    url: str
    token: str
    verify_tls: bool
    name: str = "panel"

    @property
    def api_base(self) -> str:
        """The /panel/api prefix, base path included.

        The panel serves its API under the same secret base path as the UI, so
        the base path is part of the address rather than a separate setting.
        """
        return self.url.rstrip("/") + "/panel/api"


def _read_secret_file(path: Path) -> str | None:
    if not path.is_file():
        return None
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(
            f"{path} is readable beyond its owner; run: chmod 600 {path}"
        )
    return path.read_text(encoding="utf-8").strip() or None


def _registry_dir() -> Path | None:
    raw = os.environ.get("XUI_NODES_DIR")
    if raw:
        return Path(raw).expanduser()
    return None


def _load_node(name: str) -> dict:
    """Read one node's TOML from the registry shared with the Ansible repo."""
    if tomllib is None:
        raise ConfigError("reading the node registry needs Python 3.11 or newer")
    directory = _registry_dir()
    if directory is None:
        raise ConfigError(
            f"node {name!r} requested but XUI_NODES_DIR is not set"
        )
    path = directory / f"{name}.toml"
    if not path.is_file():
        raise ConfigError(f"no such node in the registry: {path}")
    mode = path.stat().st_mode
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} is group or world readable; run: chmod 600 {path}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def list_nodes() -> list[str]:
    directory = _registry_dir()
    if directory is None or not directory.is_dir():
        return []
    return sorted(p.stem for p in directory.glob("*.toml"))


def _token_from_node(node: dict, name: str) -> str | None:
    token_file = node.get("token_file")
    if token_file:
        return _read_secret_file(Path(token_file).expanduser())
    token = node.get("token")
    if token:
        return token
    # A registry shared with Ansible may deliberately hold no token at all, in
    # which case the skill keeps its own beside the URL it belongs to.
    return _read_secret_file(SECRETS_DIR / f"token.{name}")


def resolve(
    node: str | None = None,
    url: str | None = None,
    token: str | None = None,
    token_file: str | None = None,
    verify_tls: bool | None = None,
) -> PanelConfig:
    name = node or "panel"
    node_data: dict = {}

    if node:
        node_data = _load_node(node)

    resolved_url = (
        url
        or os.environ.get("XUI_URL")
        or node_data.get("panel")
        or _read_secret_file(SECRETS_DIR / f"url.{name}")
        or _read_secret_file(SECRETS_DIR / "url")
    )

    if token_file:
        resolved_token = _read_secret_file(Path(token_file).expanduser())
    else:
        resolved_token = (
            token
            or os.environ.get("XUI_TOKEN")
            or (_token_from_node(node_data, name) if node else None)
            or _read_secret_file(SECRETS_DIR / "token")
        )

    if verify_tls is None:
        env_verify = os.environ.get("XUI_VERIFY_TLS")
        if env_verify is not None:
            verify_tls = env_verify.strip().lower() not in {"0", "false", "no"}
        elif "verify_tls" in node_data:
            verify_tls = bool(node_data["verify_tls"])
        else:
            # Panels routinely carry a certificate for a name they are not
            # reached by, or none at all. Refusing by default would make the
            # tool unusable against the common deployment.
            verify_tls = False

    if not resolved_url:
        raise ConfigError(
            "no panel URL: pass --url, set XUI_URL, write secrets/url, "
            "or name a node from the registry"
        )
    if not resolved_token:
        raise ConfigError(
            "no API token: pass --token-file, set XUI_TOKEN, or write secrets/token"
        )

    return PanelConfig(
        url=resolved_url, token=resolved_token, verify_tls=verify_tls, name=name
    )


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)
