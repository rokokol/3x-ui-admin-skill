"""Routing: read the rule chain, and check the things that fail silently.

Xray takes the first matching rule, so order is not a style question — a direct
rule below a transit rule never fires and every request leaves through the wrong
country with nothing logged. None of the failures checked here announce
themselves: the config is valid, the panel is green, the traffic is wrong.
"""

from __future__ import annotations

import json

from .. import render
from ..api import ApiError

help = "routing rules and the invariants that fail quietly"

# geoip:private already covers RFC 1918, the carrier-grade range 100.64.0.0/10,
# loopback and link-local (checked against the geoip.dat the pinned panel image
# ships). --require-blocked exists for a range it does not cover: a public
# prefix used internally, say.

# Rules that keep traffic where it is, as opposed to sending it somewhere else.
LOCAL_TAGS = {"direct", "block", "blocked"}

# Outbound tags that drop traffic. An outbound whose protocol is blackhole
# counts too, whatever it is called.
BLOCK_TAGS = {"block", "blocked"}


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    show = sub.add_parser("show", help="the rule chain in order")
    show.add_argument("--full", action="store_true", help="include every field")

    check = sub.add_parser("check", help="assert the invariants that fail silently")
    check.add_argument(
        "--direct-before",
        action="append",
        metavar="TAG",
        help="require direct/blocking rules to precede this outbound tag; repeatable",
    )
    check.add_argument(
        "--require-blocked",
        action="append",
        default=[],
        metavar="CIDR",
        help="a range geoip:private does not cover that the private block must also name; repeatable",
    )

    sub.add_parser("outbounds", help="outbound tags the rules may point at")


def _template(client) -> dict:
    # The trailing slash is required: the group is registered at "xray/" and the
    # router answers a slashless POST with a 307 that urllib will not follow.
    raw = client.post("xray/")
    try:
        if isinstance(raw, str):
            raw = json.loads(raw)
        if isinstance(raw, dict) and "xraySetting" in raw:
            # Wrapped once more, and the inner value is sometimes an object and
            # sometimes the same object as text.
            inner = raw["xraySetting"]
            return json.loads(inner) if isinstance(inner, str) else inner
    except json.JSONDecodeError as error:
        raise ApiError(f"POST xray/: the Xray template is not valid JSON: {error}") from error
    return raw or {}


def _rules(template: dict) -> list[dict]:
    return (template.get("routing") or {}).get("rules") or []


def _summarise(rule: dict) -> str:
    parts = []
    for key in ("domain", "ip", "port", "network", "protocol", "user", "inboundTag"):
        value = rule.get(key)
        if not value:
            continue
        if isinstance(value, list):
            shown = ",".join(str(v) for v in value[:3])
            if len(value) > 3:
                shown += f",+{len(value) - 3}"
        else:
            shown = str(value)
        parts.append(f"{key}={shown}")
    return " ".join(parts) or "(matches everything)"


def _block_tags(template: dict) -> set[str]:
    tags = set(BLOCK_TAGS)
    for outbound in template.get("outbounds") or []:
        if (outbound.get("protocol") or "").lower() == "blackhole" and outbound.get("tag"):
            tags.add(outbound["tag"])
    return tags


def _ip_list(rule: dict) -> list[str]:
    value = rule.get("ip") or []
    if isinstance(value, str):
        value = [value]
    return [str(v) for v in value]


def check_rules(
    template: dict,
    direct_before: list[str] | None = None,
    require_blocked: list[str] | None = None,
) -> tuple[list[str], list[str]]:
    """Return (problems, notes) for a routing table. Pure, so it can be tested."""
    rules = _rules(template)
    problems: list[str] = []
    notes: list[str] = []

    if not rules:
        return ["no routing rules at all"], notes

    # An outbound tag that does not exist makes the rule inert: traffic falls
    # through to whatever matches next, which is usually the open internet.
    known = {o.get("tag") for o in template.get("outbounds") or [] if o.get("tag")}
    known |= {b.get("tag") for b in (template.get("routing") or {}).get("balancers") or []}
    # `api` is served by the gRPC handler rather than by an outbound, so it is
    # never declared among them and is not a dangling reference.
    known.add("api")
    for index, rule in enumerate(rules):
        target = rule.get("outboundTag") or rule.get("balancerTag")
        if not target:
            # Xray closes each matching connection with "non existing outTag"
            # logged; older cores sent it to the first outbound instead.
            # Whatever the rule meant, that is not it.
            problems.append(
                f"rule {index} names no outbound; Xray drops what it matches, with a "
                "warning per connection"
            )
        elif target not in known:
            problems.append(f"rule {index} points at {target!r}, which no outbound declares")

    # Conditions inside one rule are ANDed, so a rule naming both a domain list
    # and an IP list matches only traffic satisfying both - in practice nothing.
    for index, rule in enumerate(rules):
        if rule.get("domain") and rule.get("ip"):
            problems.append(
                f"rule {index} names both domain and ip; conditions AND together, "
                "so it matches nothing. Split it in two."
            )

    # Stats and online status arrive through the api inbound, and a
    # private-address block above it swallows them.
    api_index = next(
        (
            i
            for i, r in enumerate(rules)
            if r.get("outboundTag") == "api" or "api" in (r.get("inboundTag") or [])
        ),
        None,
    )
    if api_index is None:
        notes.append("no api rule: client stats and online status will read as empty")
    elif api_index != 0:
        problems.append(
            f"the api rule is at position {api_index}, not 0; a private-address "
            "block above it silences stats"
        )

    # Anything inside the tunnel can reach the panel over its private address
    # unless a rule drops geoip:private. Naming the range is not enough: a rule
    # that routes it `direct` is the opposite of a block and looks the same.
    # The panel's own template blocks geoip:private, because a client's traffic
    # leaves with the server's address and would otherwise reach the panel on
    # loopback and everything else the server can see. Removing or rerouting
    # that rule may be deliberate, so it is shown rather than failed.
    blocking = _block_tags(template)
    private_rules = [r for r in rules if any("private" in v for v in _ip_list(r))]
    private_blocks = [r for r in private_rules if r.get("outboundTag") in blocking]
    if not private_rules:
        notes.append(
            "no rule mentions geoip:private: tunnel clients can reach the panel and "
            "the server's networks"
        )
    for rule in private_rules:
        if rule in private_blocks:
            continue
        target = rule.get("outboundTag") or rule.get("balancerTag")
        if target:
            notes.append(
                f"rule {rules.index(rule)} sends geoip:private to {target!r}; tunnel "
                "clients can reach whatever that outbound reaches"
            )
    for cidr in require_blocked or []:
        if not any(cidr in _ip_list(r) for r in private_blocks):
            problems.append(
                f"no block names {cidr}: a tunnel client reaches whatever answers "
                "in that range as a trusted peer"
            )

    # A rule that sends traffic abroad must not sit above the rules that keep
    # local traffic local, or the local ones never fire.
    for tag in direct_before or []:
        if tag in LOCAL_TAGS:
            notes.append(
                f"--direct-before {tag!r} names a local tag; the check compares "
                "transit rules against local ones and cannot compare it to itself"
            )
            continue
        transit = next((i for i, r in enumerate(rules) if r.get("outboundTag") == tag), None)
        if transit is None:
            notes.append(f"no rule targets {tag!r}; ordering not checked for it")
            continue
        for index, rule in enumerate(rules):
            if index <= transit:
                continue
            if rule.get("outboundTag") in LOCAL_TAGS:
                problems.append(
                    f"rule {index} ({rule.get('outboundTag')}) sits below the {tag!r} "
                    f"rule at {transit}; first match wins, so it never fires"
                )

    return problems, notes


def run(args, client) -> int:
    template = _template(client)
    rules = _rules(template)

    if args.command == "show":
        if args.full:
            print(render.dumps(rules, args.reveal))
            return 0
        rows = [
            {
                "#": index,
                "tag": rule.get("ruleTag") or rule.get("tag") or "-",
                "action": rule.get("outboundTag") or rule.get("balancerTag") or "-",
                "matches": _summarise(rule),
            }
            for index, rule in enumerate(rules)
        ]
        print(render.table(rows, ["#", "tag", "action", "matches"]))
        return 0

    if args.command == "outbounds":
        rows = [
            {"tag": o.get("tag") or "(untagged)", "protocol": o.get("protocol")}
            for o in template.get("outbounds") or []
        ]
        print(render.table(rows, ["tag", "protocol"]))
        return 0

    if args.command == "check":
        problems, notes = check_rules(template, args.direct_before or [], args.require_blocked)
        for note in notes:
            print(f"note: {note}")
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print(f"ok: {len(rules)} rule(s), no silent-failure pattern found")
        return 0

    print(f"unknown command: {args.command}")
    return 2
