"""Inbound invariants, each one a failure that does not announce itself.

The panel stores stream settings as raw JSON and hands them to Xray verbatim, so
a misspelled key is stored, served and ignored — the inbound works, minus the
setting you thought you set.

Findings are split in two. A problem is something broken: traffic goes to the
wrong client, or the core refuses the configuration. A note is something worth
seeing that may well be deliberate — a spare inbound with no peers, sniffing off
on a transport that does not route by name. Mixing the two makes the whole check
noise, and a noisy check gets ignored.
"""

from __future__ import annotations

import json
from typing import Any

# Protocols where a domain-based routing rule can only match if sniffing gives
# it a name to match against.
NAME_ROUTED = {"vless", "vmess", "trojan", "shadowsocks", "http", "socks"}


def _decode(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip().startswith("{"):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return {}
    return {}


def _misspelled(node: Any, correct: str, path: str = "") -> list[str]:
    """Keys that differ from the real one only by case: stored, served, ignored."""
    found = []
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else key
            if key != correct and key.lower() == correct.lower():
                found.append(
                    f"{here} is spelled {key!r}, but only {correct!r} is read; the panel "
                    "stores the rest verbatim without complaining"
                )
            found.extend(_misspelled(value, correct, here))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            found.extend(_misspelled(item, correct, f"{path}[{index}]"))
    return found


def check_inbound(inbound: dict) -> tuple[list[str], list[str]]:
    """Return (problems, notes) for one inbound."""
    problems: list[str] = []
    notes: list[str] = []
    remark = inbound.get("remark") or inbound.get("id")
    protocol = (inbound.get("protocol") or "").lower()

    settings = _decode(inbound.get("settings"))
    stream = _decode(inbound.get("streamSettings") or inbound.get("stream_settings"))
    sniffing = _decode(inbound.get("sniffing"))

    if protocol in NAME_ROUTED and sniffing:
        if not sniffing.get("enabled"):
            notes.append(
                f"{remark}: sniffing is off, so domain routing rules cannot match here"
            )
        else:
            overrides = [str(o).lower() for o in (sniffing.get("destOverride") or [])]
            if "quic" not in overrides:
                # The name lives only in the QUIC Initial packet, so without it
                # domain rules stop matching the moment a client speaks HTTP/3.
                problems.append(
                    f"{remark}: sniffing is on but destOverride lacks 'quic', so domain "
                    "rules silently stop matching over HTTP/3"
                )

    security = (stream.get("security") or "").lower()
    if security == "reality":
        reality = stream.get("realitySettings") or {}
        for field, why in (
            ("privateKey", "the inbound cannot complete a handshake"),
            ("dest", "there is no site to borrow a handshake from"),
        ):
            if not reality.get(field):
                problems.append(f"{remark}: Reality has no {field}: {why}")
        if not (reality.get("serverNames") or []):
            problems.append(f"{remark}: Reality declares no serverNames")
        if not (reality.get("shortIds") or []):
            problems.append(f"{remark}: Reality declares no shortIds")

        block = reality.get("settings") or reality
        if "minClient" in block and "minClientVer" not in block:
            problems.append(
                f"{remark}: 'minClient' is not a field. The setting is 'minClientVer'; "
                "with the typo the core keeps its default floor and modern clients fail "
                "with 'reality verification failed'"
            )
        problems.extend(f"{remark}: {m}" for m in _misspelled(stream, "minClientVer"))

    if protocol == "wireguard":
        if not settings.get("secretKey"):
            problems.append(
                f"{remark}: no secretKey. Xray refuses the entire configuration over "
                "this, so the node stops serving every inbound, not just this one"
            )
        if not settings.get("mtu"):
            notes.append(f"{remark}: no MTU declared, the client picks its own")

        peers = settings.get("peers") or []
        if not peers:
            notes.append(f"{remark}: no peers, so nothing can connect to it")

        # A peer is addressed by its tunnel IP, so a duplicate inside one inbound
        # hands one client another's traffic. Across inbounds they may repeat:
        # each WireGuard inbound builds its own stack.
        seen: dict[str, int] = {}
        for index, peer in enumerate(peers):
            for address in peer.get("allowedIPs") or []:
                if address in seen:
                    problems.append(
                        f"{remark}: peers {seen[address]} and {index} both claim tunnel "
                        f"address {address}; one client would receive the other's traffic"
                    )
                seen[address] = index

    # Spelled with a capital M it works server-side but never reaches the
    # subscription, because the link generator matches the key exactly.
    problems.extend(f"{remark}: {m}" for m in _misspelled(stream, "finalmask"))

    return problems, notes
