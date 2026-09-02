"""Where the panel is and how to authenticate to it.

Resolution order, first hit wins: explicit arguments, environment, the skill's
own secrets/ directory, then a node registry shared with an infrastructure
repository. Nothing here assumes a particular network: a panel on loopback, on
a tunnel address or on the public internet is reached the same way.

Naming a node changes the rule: a node's URL and token come from the node and
nowhere else, so an XUI_URL left exported in the shell cannot pair the node's
token with some other panel's address. Explicit flags still win, because they
were typed for this one call.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10 and older
    tomllib = None

SKILL_ROOT = Path(__file__).resolve().parent.parent
SECRETS_DIR = SKILL_ROOT / "secrets"

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


class ConfigError(Exception):
    """Raised when the panel cannot be located or authenticated."""


@dataclass
class PanelConfig:
    url: str
    token: str
    verify_tls: bool
    name: str = "panel"
    # sha256 of the panel's certificate, as 64 hex digits; authenticates the
    # peer even when its certificate matches no name and no CA.
    pin_sha256: str | None = None
    # Send the bearer token over http:// to a host that is not loopback.
    allow_plaintext: bool = False

    @property
    def api_base(self) -> str:
        """The /panel/api prefix, base path included.

        The panel serves its API under the same secret base path as the UI, so
        the base path is part of the address rather than a separate setting.
        """
        return self.url.rstrip("/") + "/panel/api"

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme.lower()

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def display_url(self) -> str:
        """The address without the base path, for messages that may be pasted."""
        parts = urlsplit(self.url)
        return f"{parts.scheme}://{parts.netloc}"

    @property
    def is_loopback(self) -> bool:
        return self.host in LOOPBACK_HOSTS or self.host.startswith("127.")


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
    """Read one node's TOML from the registry, if there is one.

    The registry is the skill's own format: a directory of `<name>.toml` files
    that whatever manages the machines may also write, or nothing else touches.
    A name with no TOML behind it is still a name: `secrets/url.<name>` and
    `secrets/token.<name>` describe a second panel without any registry.
    """
    directory = _registry_dir()
    if directory is None:
        return {}
    path = directory / f"{name}.toml"
    if not path.is_file():
        return {}
    if tomllib is None:
        raise ConfigError("reading the node registry needs Python 3.11 or newer")
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
    # A registry that some other tool writes may deliberately hold no token at
    # all, in which case the skill keeps its own beside the URL it belongs to.
    return _read_secret_file(SECRETS_DIR / f"token.{name}")


def _env_flag(name: str) -> bool | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    return raw.strip().lower() not in {"0", "false", "no", ""}


def _normalise_pin(raw: str | None, source: str) -> str | None:
    if not raw:
        return None
    pin = raw.strip().lower().replace(":", "")
    pin = pin.removeprefix("sha256/")
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        raise ConfigError(
            f"{source}: a pin is the certificate's sha256 as 64 hex digits, "
            f"got {len(pin)} characters"
        )
    return pin


def resolve(
    node: str | None = None,
    url: str | None = None,
    token: str | None = None,
    token_file: str | None = None,
    verify_tls: bool | None = None,
    pin_sha256: str | None = None,
    allow_plaintext: bool | None = None,
) -> PanelConfig:
    name = node or "panel"
    node_data: dict = {}

    if node:
        node_data = _load_node(node)
        # The environment describes some panel; a node describes this one.
        # Pairing the node's token with the environment's URL would send the
        # token to whichever panel the shell happened to be pointed at.
        for variable in ("XUI_URL", "XUI_TOKEN"):
            if os.environ.get(variable):
                warn(f"{variable} is set but ignored because --node {node} was given")
        resolved_url = (
            url
            or node_data.get("panel")
            or _read_secret_file(SECRETS_DIR / f"url.{name}")
        )
        if token_file:
            resolved_token = _read_secret_file(Path(token_file).expanduser())
        else:
            resolved_token = token or _token_from_node(node_data, name)
    else:
        resolved_url = (
            url
            or os.environ.get("XUI_URL")
            or _read_secret_file(SECRETS_DIR / "url")
        )
        if token_file:
            resolved_token = _read_secret_file(Path(token_file).expanduser())
        else:
            resolved_token = (
                token
                or os.environ.get("XUI_TOKEN")
                or _read_secret_file(SECRETS_DIR / "token")
            )

    if verify_tls is None:
        env_verify = _env_flag("XUI_VERIFY_TLS")
        if env_verify is not None and not node:
            verify_tls = env_verify
        elif "verify_tls" in node_data:
            verify_tls = bool(node_data["verify_tls"])
        else:
            # Panels routinely carry a certificate for a name they are not
            # reached by, or none at all. Refusing by default would make the
            # tool unusable against the common deployment; a pin is the way
            # to authenticate one anyway.
            verify_tls = False

    if pin_sha256 is None:
        if node:
            pin_sha256 = node_data.get("pin_sha256") or _read_secret_file(
                SECRETS_DIR / f"pin.{name}"
            )
        else:
            pin_sha256 = os.environ.get("XUI_PIN_SHA256") or _read_secret_file(
                SECRETS_DIR / "pin"
            )
    pin_sha256 = _normalise_pin(pin_sha256, "pin")

    if allow_plaintext is None:
        env_plain = _env_flag("XUI_ALLOW_PLAINTEXT")
        if env_plain is not None and not node:
            allow_plaintext = env_plain
        else:
            allow_plaintext = bool(node_data.get("allow_plaintext", False))

    if not resolved_url:
        if node:
            raise ConfigError(
                f"no panel URL for {node!r}: write secrets/url.{node}, set `panel` "
                f"in $XUI_NODES_DIR/{node}.toml, or pass --url"
            )
        raise ConfigError(
            "no panel URL: pass --url, set XUI_URL, write secrets/url, "
            "or name a node from the registry"
        )
    if not resolved_token:
        if node:
            raise ConfigError(
                f"no API token for {node!r}: write secrets/token.{node}, set `token` "
                f"or `token_file` in $XUI_NODES_DIR/{node}.toml, or pass --token-file"
            )
        raise ConfigError(
            "no API token: pass --token-file, set XUI_TOKEN, or write secrets/token"
        )

    config = PanelConfig(
        url=resolved_url,
        token=resolved_token,
        verify_tls=verify_tls,
        name=name,
        pin_sha256=pin_sha256,
        allow_plaintext=allow_plaintext,
    )
    if config.scheme not in {"http", "https"}:
        raise ConfigError(f"panel URL must start with http:// or https://, got {config.display_url}")
    if config.scheme == "http" and not config.is_loopback and not config.allow_plaintext:
        raise ConfigError(
            f"{config.display_url} is plain http: the API token would travel in "
            "clear text. Use https://, or pass --allow-plaintext if the network "
            "itself is trusted"
        )
    if config.pin_sha256 and config.scheme != "https":
        raise ConfigError("a certificate pin needs an https:// URL")
    return config


def warn(message: str) -> None:
    print(f"warning: {message}", file=sys.stderr)
