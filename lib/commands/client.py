"""Clients: the people and devices attached to inbounds.

In this panel a client is a row of its own, attached to any number of inbounds
through a join table, and its `flow` is stored per attachment. Reads therefore
show a derived flow rather than a stored column; writes have to name every
field they want to keep, which is what the edit commands guard against.
"""

from __future__ import annotations

import time

from .. import render

help = "clients and their attachments"


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    listing = sub.add_parser("list", help="one line per client")
    listing.add_argument("--inbound", type=int, help="only clients on this inbound")
    listing.add_argument("--disabled", action="store_true", help="only disabled clients")

    get = sub.add_parser("get", help="one client in full, credentials masked")
    get.add_argument("email", help="the client's email/label")

    traffic = sub.add_parser("traffic", help="usage per client, largest first")
    traffic.add_argument("--top", type=int, default=20)

    idle = sub.add_parser("idle", help="clients that have not connected recently")
    idle.add_argument("--days", type=int, default=30)

    sub.add_parser("orphans", help="clients left behind by a deleted inbound")

    sub.add_parser("online", help="clients seen connected right now")


def _label(value, reveal: bool) -> str:
    return value if reveal else render.mask_label(value)


def _ms_age_days(value) -> float | None:
    """Panel timestamps are milliseconds; return age in days, None if never."""
    if not value:
        return None
    seconds = value / 1000 if value > 10_000_000_000 else value
    return (time.time() - seconds) / 86400


def _expiry(value) -> str:
    if not value:
        return "never"
    seconds = value / 1000 if value > 10_000_000_000 else value
    remaining = seconds - time.time()
    if remaining < 0:
        return "expired"
    return f"{remaining / 86400:.0f}d"


def _usage(item: dict) -> tuple[int, int]:
    """Traffic counters live in a nested object, not on the client itself."""
    traffic = item.get("traffic") or {}
    return traffic.get("up") or 0, traffic.get("down") or 0


def run(args, client) -> int:
    if args.command == "list":
        clients = client.get("clients/list") or []
        rows = []
        for item in clients:
            if args.disabled and item.get("enable"):
                continue
            inbound_ids = item.get("inboundIds") or []
            if args.inbound and args.inbound not in inbound_ids:
                continue
            up, down = _usage(item)
            rows.append(
                {
                    "email": _label(item.get("email"), args.reveal),
                    "enable": "yes" if item.get("enable") else "NO",
                    "flow": item.get("flow") or "-",
                    "inbounds": ",".join(str(i) for i in inbound_ids) or "-",
                    "used": render.human_bytes(up + down),
                    "limit": render.human_bytes(item.get("totalGB")) if item.get("totalGB") else "-",
                    "expiry": _expiry(item.get("expiryTime")),
                }
            )
        if args.json:
            print(render.dumps(rows, args.reveal))
        else:
            print(render.table(rows, ["email", "enable", "flow", "inbounds", "used", "limit", "expiry"]))
        return 0

    if args.command == "get":
        item = client.get(f"clients/get/{args.email}")
        print(render.dumps(item, args.reveal))
        return 0

    if args.command == "traffic":
        clients = client.get("clients/list") or []
        ranked = sorted(clients, key=lambda c: sum(_usage(c)), reverse=True)[: args.top]
        out = []
        for c in ranked:
            up, down = _usage(c)
            last = _ms_age_days((c.get("traffic") or {}).get("lastOnline"))
            out.append(
                {
                    "email": _label(c.get("email"), args.reveal),
                    "up": render.human_bytes(up),
                    "down": render.human_bytes(down),
                    "total": render.human_bytes(up + down),
                    "last seen": "never" if last is None else f"{last:.1f}d ago",
                }
            )
        if args.json:
            print(render.dumps(out, args.reveal))
        else:
            print(render.table(out, ["email", "up", "down", "total", "last seen"]))
        return 0

    if args.command == "idle":
        clients = client.get("clients/list") or []
        rows = []
        for c in clients:
            last = _ms_age_days((c.get("traffic") or {}).get("lastOnline"))
            if last is not None and last < args.days:
                continue
            up, down = _usage(c)
            rows.append(
                {
                    "email": _label(c.get("email"), args.reveal),
                    "enable": "yes" if c.get("enable") else "NO",
                    "last seen": "never" if last is None else f"{last:.0f}d ago",
                    "used": render.human_bytes(up + down),
                }
            )
        if not rows:
            print(f"ok: every client connected within {args.days} days")
            return 0
        print(render.table(rows, ["email", "enable", "last seen", "used"]))
        return 0

    if args.command == "orphans":
        # Deleting an inbound leaves its clients behind; deleting a client is
        # clean. This is the report half of that asymmetry.
        clients = client.get("clients/list") or []
        orphans = [c for c in clients if not (c.get("inboundIds") or [])]
        if not orphans:
            print("ok: no orphaned clients")
            return 0
        rows = [
            {
                "email": _label(c.get("email"), args.reveal),
                "traffic": render.human_bytes(sum(_usage(c))),
            }
            for c in orphans
        ]
        print(render.table(rows, ["email", "traffic"]))
        print(f"\n{len(orphans)} orphan(s). Remove with: POST clients/delOrphans")
        return 1

    if args.command == "online":
        online = client.get("clients/onlines") or []
        if not online:
            print("(nobody connected)")
            return 0
        for email in online:
            print(_label(email, args.reveal))
        return 0

    print(f"unknown command: {args.command}")
    return 2
