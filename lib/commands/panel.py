"""Panel settings: read any key, change any key, know which ones bite.

`setting/update` binds the whole settings struct, so it replaces rather than
patches exactly like the client endpoint does. Every write here is therefore a
read-modify-write of all ~112 keys, and the same snapshot-and-verify rule applies.

Keys are sorted into three classes because the consequences differ in kind. Most
are safe. Some are correct to change but invalidate what has already been handed
to clients. A few describe how this machine is reached, and getting one wrong
locks you out of the panel with no way back through the API.
"""

from __future__ import annotations

import json
import socket
import ssl

from .. import render, snapshot
from ..api import fingerprint

help = "read and write panel settings"

# Settings that describe *this machine* rather than the configuration it serves.
# A wrong value here answers on an address nobody can reach, presents a
# certificate that does not exist, or makes the panel impersonate another node.
# Recovery is over SSH with `x-ui setting`, not through this API.
HOST_BOUND = {
    "webListen",
    "webDomain",
    "webPort",
    "webCertFile",
    "webKeyFile",
    "webBasePath",
    "subListen",
    "subDomain",
    "subPort",
    "subCertFile",
    "subKeyFile",
    "subURI",
    "subJsonURI",
    "secret",
    "panelGuid",
    "nodeMtlsCaCertPem",
    "nodeMtlsCaKeyPem",
    "nodeMtlsClientCertPem",
    "nodeMtlsClientKeyPem",
    "nodeMtlsClientCertSha256",
    "nodeMtlsClientCAPem",
}

# Correct to change, but every subscription link already distributed stops
# resolving the moment they do. Hand out the new links in the same sitting.
BREAKS_ISSUED_LINKS = {
    "subPath",
    "subJsonPath",
    "subClashPath",
    "subEncrypt",
}

# Presence flags the panel adds when reading; they are not settings and the
# write endpoint does not know them.
READ_ONLY_FLAGS_PREFIX = "has"


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    listing = sub.add_parser("list", help="every setting, or those matching a pattern")
    listing.add_argument("pattern", nargs="?", help="substring, case-insensitive")
    listing.add_argument("--class", dest="klass", choices=["safe", "breaking", "host"],
                         help="only settings of this consequence class")

    get = sub.add_parser("get", help="one setting")
    get.add_argument("key")

    cert = sub.add_parser("cert", help="sha256 of the certificate the panel presents, for pinning")
    cert.set_defaults(needs_panel=True)

    setter = sub.add_parser("set", help="change settings, verifying nothing else moved")
    setter.add_argument("assignments", nargs="+", metavar="KEY=VALUE")
    setter.add_argument(
        "--i-understand",
        action="store_true",
        help="required for keys that break issued links or can lock you out",
    )


def _classify(key: str) -> str:
    if key in HOST_BOUND:
        return "host"
    if key in BREAKS_ISSUED_LINKS:
        return "breaking"
    return "safe"


def _consequence(key: str) -> str:
    if key in HOST_BOUND:
        return (
            f"{key} describes how this panel is reached. A wrong value leaves it "
            "unreachable and only SSH can undo it."
        )
    if key in BREAKS_ISSUED_LINKS:
        return (
            f"{key} changes where subscriptions live. Every link already handed out "
            "stops working; reissue them in the same sitting."
        )
    return ""


def _reader(client):
    def read() -> dict:
        settings = client.post("setting/all")
        if not isinstance(settings, dict):
            raise snapshot.MutationError("setting/all did not return an object")
        return settings

    return read


def _writer(client):
    def write(obj: dict) -> None:
        body = {
            k: v
            for k, v in obj.items()
            if not (k.startswith(READ_ONLY_FLAGS_PREFIX) and isinstance(v, bool))
        }
        client.post("setting/update", form=_flatten(body))

    return write


def _flatten(obj: dict) -> dict:
    """The settings endpoint takes form fields, not JSON.

    A structured value has to travel as JSON text: `str()` of a list is Python
    syntax, which the panel would store verbatim and then fail to parse.
    """
    out = {}
    for key, value in obj.items():
        if isinstance(value, bool):
            out[key] = "true" if value else "false"
        elif value is None:
            out[key] = ""
        elif isinstance(value, (list, dict)):
            out[key] = json.dumps(value)
        else:
            out[key] = str(value)
    return out


def _coerce(current, raw: str):
    if isinstance(current, bool):
        lowered = raw.strip().lower()
        if lowered in {"true", "yes", "1", "on"}:
            return True
        if lowered in {"false", "no", "0", "off"}:
            return False
        raise ValueError(f"expected true or false, got {raw!r}")
    if isinstance(current, int):
        return int(raw)
    return raw


def _presented_certificate(host: str, port: int) -> bytes:
    """The certificate the panel presents, without sending the token.

    The TLS handshake is the whole exchange: nothing is verified, nothing is
    requested, so this is safe to run against an address that is not yet
    trusted - that is precisely when a pin is taken.
    """
    context = ssl._create_unverified_context()
    with (
        socket.create_connection((host, port), timeout=15) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        return tls.getpeercert(binary_form=True) or b""


def run(args, client) -> int:
    if args.command == "cert":
        config = client.config
        if config.scheme != "https":
            print(f"{config.display_url} is not https; there is no certificate to pin")
            return 2
        from urllib.parse import urlsplit

        parts = urlsplit(config.url)
        try:
            der = _presented_certificate(parts.hostname or "", parts.port or 443)
        except OSError as error:
            print(f"cannot reach {config.display_url}: {error}")
            return 1
        seen = fingerprint(der)
        print(f"sha256:{seen}")
        if config.pin_sha256:
            if seen == config.pin_sha256:
                print("matches the configured pin")
                return 0
            print("DOES NOT MATCH the configured pin")
            return 1
        print("\nTo pin it: printf '%s' '" + seen + "' > secrets/pin && chmod 600 secrets/pin")
        return 0

    if args.command == "list":
        settings = _reader(client)()
        rows = []
        for key in sorted(settings):
            if key.startswith(READ_ONLY_FLAGS_PREFIX) and isinstance(settings[key], bool):
                continue
            if args.pattern and args.pattern.lower() not in key.lower():
                continue
            klass = _classify(key)
            if args.klass and klass != args.klass:
                continue
            rows.append(
                {
                    "key": key,
                    "class": klass,
                    "value": render.redact({key: settings[key]}, args.reveal)[key],
                }
            )
        if args.json:
            print(render.dumps(rows, args.reveal))
        else:
            print(render.table(rows, ["key", "class", "value"]))
        return 0

    if args.command == "get":
        settings = _reader(client)()
        if args.key not in settings:
            print(f"no such setting: {args.key}")
            return 2
        value = render.redact({args.key: settings[args.key]}, args.reveal)[args.key]
        print(f"{args.key} = {value!r}   [{_classify(args.key)}]")
        note = _consequence(args.key)
        if note:
            print(f"\n{note}")
        return 0

    if args.command == "set":
        settings = _reader(client)()
        changes = {}
        warnings = []
        for assignment in args.assignments:
            if "=" not in assignment:
                print(f"not a KEY=VALUE pair: {assignment}")
                return 2
            key, _, raw = assignment.partition("=")
            if key not in settings:
                print(f"no such setting: {key}")
                return 2
            try:
                changes[key] = _coerce(settings[key], raw)
            except ValueError as error:
                print(f"{key}: {error}")
                return 2
            note = _consequence(key)
            if note:
                warnings.append(note)

        if warnings and not args.i_understand:
            for note in warnings:
                print(note)
            print("\nRe-run with --i-understand to proceed.")
            return 2

        try:
            applied = snapshot.apply_and_verify(
                _reader(client), _writer(client), changes
            )
        except snapshot.MutationError as error:
            print(f"REFUSED: {error}")
            return 1

        if not applied:
            print("no change (the values were already set)")
            return 0
        print("applied:")
        print(applied.describe())
        if any(k in BREAKS_ISSUED_LINKS for k in changes):
            print("\nIssued subscription links are now dead. New ones: xui sub links")
        return 0

    print(f"unknown command: {args.command}")
    return 2
