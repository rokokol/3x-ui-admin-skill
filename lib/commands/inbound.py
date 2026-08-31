"""Inbounds: list, read, and check their settings."""

from __future__ import annotations

import json

from .. import render
from ..inbound_checks import check_inbound

help = "inspect and edit inbounds"


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    listing = sub.add_parser("list", help="one line per inbound")
    listing.add_argument("--all", action="store_true", help="include disabled ones")

    get = sub.add_parser("get", help="full inbound, credentials masked")
    get.add_argument("id", type=int)

    settings = sub.add_parser("settings", help="decoded stream settings of one inbound")
    settings.add_argument("id", type=int)

    validate = sub.add_parser("validate", help="check inbounds for silent misconfiguration")
    validate.add_argument("id", nargs="?", type=int, help="one inbound, or omit for all")


def _decode(value):
    """Inbound sub-objects are stored as JSON *text*, not as JSON."""
    if isinstance(value, str) and value.strip().startswith(("{", "[")):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def run(args, client) -> int:
    if args.command == "list":
        inbounds = client.get("inbounds/list") or []
        rows = []
        for item in inbounds:
            if not args.all and not item.get("enable"):
                continue
            rows.append(
                {
                    "id": item.get("id"),
                    "remark": item.get("remark"),
                    "protocol": item.get("protocol"),
                    "port": item.get("port"),
                    "enable": "yes" if item.get("enable") else "no",
                    "node": item.get("nodeId") or item.get("node_id") or "local",
                    "up": render.human_bytes(item.get("up")),
                    "down": render.human_bytes(item.get("down")),
                }
            )
        if args.json:
            print(render.dumps(rows, args.reveal))
        else:
            print(
                render.table(
                    rows,
                    ["id", "remark", "protocol", "port", "enable", "node", "up", "down"],
                )
            )
        return 0

    if args.command == "get":
        item = client.get(f"inbounds/get/{args.id}")
        print(render.dumps(item, args.reveal))
        return 0

    if args.command == "settings":
        item = client.get(f"inbounds/get/{args.id}")
        decoded = {
            "settings": _decode(item.get("settings")),
            "streamSettings": _decode(item.get("streamSettings")),
            "sniffing": _decode(item.get("sniffing")),
        }
        print(render.dumps(decoded, args.reveal))
        return 0

    if args.command == "validate":
        if args.id:
            inbounds = [client.get(f"inbounds/get/{args.id}")]
        else:
            inbounds = client.get("inbounds/list") or []
        problems, notes = [], []
        for item in inbounds:
            found, seen = check_inbound(item)
            problems.extend(found)
            notes.extend(seen)
        for note in notes:
            print(f"note: {note}")
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print(f"ok: {len(inbounds)} inbound(s), nothing silently misconfigured")
        return 0

    print(f"unknown command: {args.command}")
    return 2
