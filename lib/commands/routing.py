"""Routing: read the rule chain, and check the things that fail silently.

Xray takes the first matching rule, so order is not a style question — a direct
rule below a transit rule never fires and every request leaves through the wrong
country with nothing logged. None of the failures checked here announce
themselves: the config is valid, the panel is green, the traffic is wrong.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sys

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

    test = sub.add_parser("test", help="ask the running core where a destination would go")
    test.add_argument(
        "probe",
        nargs="*",
        metavar="DEST[=EXPECT]",
        help="domain or IP, optionally with the outbound tag it must resolve to",
    )
    test.add_argument(
        "--from-file",
        dest="from_file",
        metavar="PATH",
        help="read probes from a file, one per line; # starts a comment",
    )
    test.add_argument("--inbound", metavar="TAG", help="arrive on this inbound tag")
    test.add_argument("--port", type=int, default=443, help="destination port (default 443)")
    test.add_argument("--network", default="tcp", choices=("tcp", "udp"))
    test.add_argument(
        "--protocol",
        default="tls",
        help="sniffed protocol the rules may match: tls, http, bittorrent (default tls)",
    )
    test.add_argument("--email", metavar="LABEL", help="client label, for user-based rules")

    snapshot = sub.add_parser("snapshot", help="write the whole template to a file, for rollback")
    snapshot.add_argument("path", metavar="PATH", help="file to write; created mode 600")

    restore = sub.add_parser("restore", help="put a snapshot back and prove the panel took it")
    restore.add_argument("path", metavar="PATH", help="a file written by `routing snapshot`")
    restore.add_argument(
        "--i-understand",
        dest="i_understand",
        action="store_true",
        help="required: this replaces the whole template for every client at once",
    )


def _envelope(client) -> dict:
    """The whole getXraySetting response: the template and the fields beside it.

    `outboundTestUrl` is one of those, and it has to travel back on a write: the
    update endpoint reads it from the same form and substitutes a default when
    the field is absent, so a save that carries only the template quietly
    replaces whatever the panel had.
    """
    # The trailing slash is required: the group is registered at "xray/" and the
    # router answers a slashless POST with a 307 that urllib will not follow.
    raw = client.post("xray/")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as error:
            raise ApiError(f"POST xray/: the response is not valid JSON: {error}") from error
    return raw if isinstance(raw, dict) else {}


def _template(client, envelope: dict | None = None) -> dict:
    raw = _envelope(client) if envelope is None else envelope
    try:
        if "xraySetting" in raw:
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


# Prefixes that name a literal rather than a database lookup. Anything else
# carrying a colon is a geosite:/geoip:/ext: reference the panel resolves
# against a .dat file it may not have.
LITERAL_DOMAIN_PREFIXES = ("domain:", "full:", "regexp:", "keyword:")


def default_outbound(template: dict) -> str:
    """Where traffic goes when no rule matches: the first outbound, not `direct`.

    Naming it matters for reading a test result. The core reports "no rule
    matched" rather than an outbound, and on a node whose first outbound is a
    transit tunnel that silence means abroad, not out of the local interface.
    """
    for outbound in template.get("outbounds") or []:
        if outbound.get("tag"):
            return str(outbound["tag"])
    return "(no outbound declared)"


def parse_probe(text: str) -> tuple[str, str, str | None]:
    """"ifconfig.me=blocked" -> ("domain", "ifconfig.me", "blocked")."""
    destination, _, expected = text.partition("=")
    destination = destination.strip()
    expected = expected.strip() or None
    if not destination:
        raise ValueError(f"probe {text!r} names no destination")
    try:
        ipaddress.ip_address(destination)
    except ValueError:
        return "domain", destination, expected
    return "ip", destination, expected


def read_probes(path: str) -> list[str]:
    probes = []
    with open(path) as handle:
        for line in handle:
            line = line.split("#", 1)[0].strip()
            if line:
                probes.append(line)
    return probes


def probe_verdict(result: dict, fallthrough: str, expected: str | None) -> tuple[str, bool, bool]:
    """(outbound the core would use, whether a rule matched, whether it was expected)."""
    tag = (result or {}).get("outboundTag") or ""
    matched = bool((result or {}).get("matched")) and bool(tag)
    outbound = tag if tag else fallthrough
    return outbound, matched, expected is None or expected == outbound


def geodata_tokens(template: dict) -> tuple[list[str], list[str]]:
    """The geosite:/geoip:/ext: references the rules make, split by which file they read."""
    site: set[str] = set()
    addresses: set[str] = set()
    for rule in _rules(template):
        value = rule.get("domain") or []
        for entry in [value] if isinstance(value, str) else value:
            entry = str(entry)
            if ":" in entry and not entry.startswith(LITERAL_DOMAIN_PREFIXES):
                site.add(entry)
        for entry in _ip_list(rule):
            if entry.startswith(("geoip:", "ext:")):
                addresses.add(entry)
    return sorted(site), sorted(addresses)


def geodata_problems(entries) -> list[str]:
    """Turn the panel's validation answer into problems.

    A misspelled category is stored without complaint, matches nothing while it
    sits there, and stops the core dead at its next start. Nothing else in the
    chain says so: the rule reads fine and the panel stays green.
    """
    problems = []
    for entry in entries or []:
        token = entry.get("token", "?")
        reason = entry.get("reason", "unresolvable")
        where = entry.get("file") or "the geo files"
        problems.append(
            f"{token}: {reason} in {where}; the rule matches nothing and the next "
            "core start refuses the config"
        )
    return problems


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
    envelope = _envelope(client)
    template = _template(client, envelope)
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
        site, addresses = geodata_tokens(template)
        for kind, tokens in (("site", site), ("ip", addresses)):
            if not tokens:
                continue
            try:
                answer = client.post(
                    "xray/geodata/validate", form={"kind": kind, "tokens": ",".join(tokens)}
                )
            except ApiError as error:
                # Say so rather than passing: an unchecked reference is not a
                # checked one, and this is the half that fails quietly.
                notes.append(f"{len(tokens)} geo {kind} reference(s) not validated: {error}")
                continue
            problems += geodata_problems(answer)
        for note in notes:
            print(f"note: {note}")
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print(f"ok: {len(rules)} rule(s), no silent-failure pattern found")
        return 0

    if args.command == "test":
        probes = list(args.probe or [])
        if args.from_file:
            probes += read_probes(args.from_file)
        if not probes:
            print("routing test: no probes given", file=sys.stderr)
            return 2

        fallthrough = default_outbound(template)
        rows, failures = [], 0
        for entry in probes:
            try:
                kind, destination, expected = parse_probe(entry)
            except ValueError as error:
                print(f"routing test: {error}", file=sys.stderr)
                return 2
            form = {kind: destination, "port": str(args.port), "network": args.network}
            if args.protocol:
                form["protocol"] = args.protocol
            if args.inbound:
                form["inboundTag"] = args.inbound
            if args.email:
                form["email"] = args.email
            outbound, matched, ok = probe_verdict(
                client.post("xray/routeTest", form=form), fallthrough, expected
            )
            failures += not ok
            rows.append(
                {
                    "destination": destination,
                    "outbound": outbound,
                    "by": "rule" if matched else "no rule",
                    "expected": expected or "-",
                    "verdict": "ok" if ok else "MISMATCH",
                }
            )

        if args.json:
            print(render.dumps(rows, args.reveal))
        else:
            print(render.table(rows, ["destination", "outbound", "by", "expected", "verdict"]))
        if failures:
            print(f"{failures} of {len(rows)} probe(s) took an outbound they were not expected to")
            return 1
        return 0

    if args.command == "snapshot":
        # 600, and never printed: an outbound in the template can carry the
        # credential this node uses to reach the next one.
        handle = os.fdopen(
            os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w"
        )
        with handle:
            json.dump(template, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        print(f"{args.path}: {len(rules)} rule(s), mode 600")
        return 0

    if args.command == "restore":
        with open(args.path) as source:
            try:
                wanted = json.load(source)
            except json.JSONDecodeError as error:
                print(f"{args.path}: not valid JSON: {error}", file=sys.stderr)
                return 2
        if not isinstance(wanted, dict) or not _rules(wanted):
            print(f"{args.path}: no routing.rules, so this is not a template", file=sys.stderr)
            return 2

        problems, _ = check_rules(wanted)
        if not args.i_understand:
            print(
                f"restore replaces the whole template — routing, outbounds, policy, log — "
                f"for every client at once.\n"
                f"  now: {len(rules)} rule(s)\n"
                f"  {args.path}: {len(_rules(wanted))} rule(s)"
            )
            for problem in problems:
                print(f"  FAIL the file itself: {problem}")
            print("\nRe-run with --i-understand to proceed.")
            return 2
        for problem in problems:
            print(f"warning: the file itself: {problem}")

        test_url = envelope.get("outboundTestUrl") or ""
        client.post(
            "xray/update",
            form={
                "xraySetting": json.dumps(wanted, ensure_ascii=False),
                "outboundTestUrl": test_url,
            },
        )
        readback = _template(client)
        if readback != wanted:
            moved = sorted(
                key
                for key in set(readback) | set(wanted)
                if readback.get(key) != wanted.get(key)
            )
            print(
                f"the panel did not store what the file holds; it differs in: {', '.join(moved)}",
                file=sys.stderr,
            )
            return 1
        print(f"restored {len(_rules(wanted))} rule(s); the panel reads back exactly the file")
        return 0

    print(f"unknown command: {args.command}")
    return 2
