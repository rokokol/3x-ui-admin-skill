"""Nodes: the master's view of the panels it drives.

A node is an ordinary 3x-ui panel that some other panel holds a token for. The
master polls it; the node never calls back. So everything here is read from the
master, and "is the link healthy" means "did the master's last poll succeed".
"""

from __future__ import annotations

import ipaddress
import time
from datetime import UTC, datetime

from .. import render
from ..api import strip_paths

help = "master to node links"

# Reachability modes the panel offers. Only two of them authenticate the peer:
# `pin` compares a certificate fingerprint, `mtls` validates a chain and
# presents a client certificate. `verify` and `skip` both skip verification
# despite the name, so a link on either is trusting its network, not its TLS.
VERIFYING_MODES = {"pin", "mtls"}


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    listing = sub.add_parser("list", help="one line per node")
    listing.set_defaults(needs_panel=True)

    health = sub.add_parser("health", help="status, heartbeat age and versions")
    health.add_argument(
        "--max-age",
        type=int,
        default=120,
        help="seconds before a heartbeat counts as stale (default 120)",
    )

    check = sub.add_parser(
        "link-check", help="assert the link's security properties have not weakened"
    )
    check.add_argument(
        "--expect-mode",
        help="require this tls_verify_mode (pin or mtls to actually authenticate)",
    )
    check.add_argument(
        "--require-private",
        nargs="?",
        const="private",
        metavar="CIDR",
        help="require every node address to be private (RFC 1918 or 100.64/10), "
        "or inside this range",
    )
    check.add_argument("--max-age", type=int, default=120)

    registry = sub.add_parser("registry", help="node names known to $XUI_NODES_DIR")
    registry.set_defaults(needs_panel=False)


def _epoch_seconds(value) -> float | None:
    """A timestamp as the panel might spell it: ms, s, or an RFC 3339 string."""
    if isinstance(value, bool) or not value:
        return None
    if isinstance(value, (int, float)):
        # The panel stores milliseconds; a value in seconds would be some
        # time in 1970.
        return value / 1000 if value > 10_000_000_000 else float(value)
    if isinstance(value, str):
        text = value.strip()
        if text.isdigit():
            return _epoch_seconds(int(text))
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        return parsed.timestamp()
    return None


def _heartbeat_age(node: dict) -> float | None:
    seconds = _epoch_seconds(node.get("lastHeartbeat") or node.get("last_heartbeat"))
    if seconds is None:
        return None
    return max(0.0, time.time() - seconds)


def _pct(value) -> str:
    try:
        return f"{float(value):.1f}%"
    except (TypeError, ValueError):
        return "?"


def _mode(node: dict) -> str:
    return node.get("tlsVerifyMode") or node.get("tls_verify_mode") or "verify"


def _address(node: dict) -> str:
    return node.get("address") or ""


# What "private" means for a node address: RFC 1918, the carrier-grade range
# 100.64.0.0/10 that tailnets and some providers use (the address library does
# not count it as private), loopback, link-local and their IPv6 equivalents.
PRIVATE_RANGES = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fc00::/7",
        "fe80::/10",
        "::1/128",
    )
)


def _inside(address: str, required: str) -> bool:
    """Whether an address is private, or inside the range asked for."""
    parsed = ipaddress.ip_address(address)
    if required == "private":
        return any(parsed in network for network in PRIVATE_RANGES)
    return parsed in ipaddress.ip_network(required, strict=False)


def run(args, client) -> int:
    if args.command == "registry":
        from .. import config as config_module

        names = config_module.list_nodes()
        print("\n".join(names) if names else "(registry empty or XUI_NODES_DIR unset)")
        return 0

    nodes = client.get("nodes/list") or []

    if args.command == "list":
        rows = [
            {
                "id": n.get("id"),
                "name": n.get("name"),
                "address": _address(n),
                "port": n.get("port"),
                "scheme": n.get("scheme"),
                "tls": _mode(n),
                "enable": "yes" if n.get("enable") else "no",
                "status": n.get("status"),
            }
            for n in nodes
        ]
        if args.json:
            print(render.dumps(rows, args.reveal))
        else:
            print(render.table(rows, ["id", "name", "address", "port", "scheme", "tls", "enable", "status"]))
        return 0

    if args.command == "health":
        rows = []
        for n in nodes:
            age = _heartbeat_age(n)
            rows.append(
                {
                    "name": n.get("name"),
                    "status": n.get("status"),
                    "heartbeat": "never" if age is None else f"{age:.0f}s ago",
                    "latency": f"{n.get('latencyMs') or n.get('latency_ms') or '?'} ms",
                    "panel": n.get("panelVersion") or n.get("panel_version"),
                    "xray": n.get("xrayVersion") or n.get("xray_version"),
                    "cpu": _pct(n.get("cpuPct") or n.get("cpu_pct")),
                    "mem": _pct(n.get("memPct") or n.get("mem_pct")),
                    "error": strip_paths(str(n.get("lastError") or n.get("last_error") or ""))[:40],
                }
            )
        if args.json:
            print(render.dumps(rows, args.reveal))
        else:
            columns = ["name", "status", "heartbeat", "latency", "panel", "xray", "cpu", "mem", "error"]
            print(render.table(rows, columns))
        return 0

    if args.command == "link-check":
        problems: list[str] = []
        for n in nodes:
            name = n.get("name") or n.get("id")
            if not n.get("enable"):
                continue

            status = (n.get("status") or "").lower()
            if status != "online":
                problems.append(f"{name}: status is {status or 'unknown'}, not online")

            age = _heartbeat_age(n)
            if age is None:
                problems.append(f"{name}: no heartbeat recorded")
            elif age > args.max_age:
                problems.append(f"{name}: last heartbeat {age:.0f}s ago (limit {args.max_age}s)")

            mode = _mode(n)
            if args.expect_mode and mode != args.expect_mode:
                problems.append(f"{name}: tls_verify_mode is {mode}, expected {args.expect_mode}")
            if mode == "pin" and not (n.get("pinnedCertSha256") or n.get("pinned_cert_sha256")):
                problems.append(f"{name}: mode is pin but no fingerprint is stored")

            address = _address(n)
            if args.require_private and address:
                try:
                    if not _inside(address, args.require_private):
                        problems.append(
                            f"{name}: address {address} is outside {args.require_private} "
                            "while the link does not verify TLS"
                        )
                except ValueError:
                    problems.append(f"{name}: address {address} is a name, not an address")

            if mode not in VERIFYING_MODES and not args.require_private:
                print(
                    f"note: {name} uses tls_verify_mode={mode}, which authenticates "
                    "nothing; the network is the only thing protecting this link"
                )

        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print(f"ok: {len([n for n in nodes if n.get('enable')])} enabled node(s) healthy")
        return 0

    print(f"unknown command: {args.command}")
    return 2
