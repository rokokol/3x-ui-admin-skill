"""Subscriptions: the links clients actually use, and where they point.

A subscription link is a bearer credential for the VPN — anyone holding it can
connect. So links are never printed to a terminal by default: they go to a file
with owner-only permissions, or to the screen only when asked for explicitly.
"""

from __future__ import annotations

import os
from pathlib import Path

from .. import render

help = "subscription links and their settings"


def register(parser) -> None:
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    links = sub.add_parser("links", help="links for one client, or for everyone")
    links.add_argument("email", nargs="?", help="omit for every client")
    links.add_argument("-o", "--out", help="write to this file (mode 600) instead of stdout")
    links.add_argument(
        "--print",
        dest="to_stdout",
        action="store_true",
        help="print the links; they are credentials, so this is deliberate",
    )

    sub.add_parser("settings", help="where subscriptions are served from")

    sub.add_parser("check", help="assert the subscription service is coherent")


def _sub_settings(client) -> dict:
    return client.post("setting/all") or {}


def _links_for(client, email: str) -> list[str]:
    result = client.get(f"clients/links/{email}")
    if isinstance(result, list):
        return [str(item) for item in result]
    if isinstance(result, str):
        return [line for line in result.splitlines() if line.strip()]
    return []


def run(args, client) -> int:
    if args.command == "settings":
        settings = _sub_settings(client)
        keys = [
            "subEnable",
            "subListen",
            "subPort",
            "subPath",
            "subJsonPath",
            "subClashPath",
            "subDomain",
            "subURI",
            "subEncrypt",
            "subTitle",
            "subCertFile",
            "subKeyFile",
        ]
        rows = [{"key": k, "value": settings.get(k)} for k in keys if k in settings]
        print(render.table(rows, ["key", "value"]))

        if settings.get("subPath") == "/sub/" or settings.get("subJsonPath") == "/json/":
            print(
                "\nnote: the default paths are guessable, and the server tells an "
                "attacker when a guess is right: an existing path answers 404 with an "
                "empty body while an unknown one answers 404 with a message. Changing "
                "them invalidates every link already handed out."
            )
        return 0

    if args.command == "check":
        settings = _sub_settings(client)
        problems = []
        notes = []

        if not settings.get("subEnable"):
            print("subscriptions are disabled on this panel")
            return 0

        if not settings.get("subDomain"):
            problems.append(
                "subDomain is empty: the service answers on any Host, including a bare "
                "address, so a scanner that finds the port finds the service"
            )
        if settings.get("subListen") in ("", None):
            notes.append(
                "subListen is empty, so the service binds every interface; the firewall "
                "is the only thing narrowing who reaches it"
            )
        for name in ("subCertFile", "subKeyFile"):
            if not settings.get(name):
                problems.append(f"{name} is empty: subscriptions would be served without TLS")

        uri = settings.get("subURI") or ""
        path = settings.get("subPath") or ""
        if uri and path and not uri.rstrip("/").endswith(path.strip("/")):
            problems.append(
                f"subURI ({uri}) does not end with subPath ({path}); generated links "
                "would point somewhere the service does not serve"
            )

        for note in notes:
            print(f"note: {note}")
        if problems:
            for problem in problems:
                print(f"FAIL {problem}")
            return 1
        print("ok: subscription service is coherent")
        return 0

    if args.command == "links":
        if args.email:
            targets = [args.email]
        else:
            clients = client.get("clients/list") or []
            targets = [c["email"] for c in clients if c.get("email")]

        collected: list[tuple[str, list[str]]] = []
        for email in targets:
            try:
                collected.append((email, _links_for(client, email)))
            except Exception as error:  # noqa: BLE001 - one bad client must not stop the rest
                print(f"warning: {render.mask_label(email)}: {error}")

        if args.out:
            destination = Path(args.out)
            # Created 600 before anything is written: a link is a credential, and
            # a default-umask file would be readable by the whole machine first.
            handle = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(handle, "w", encoding="utf-8") as stream:
                for email, links in collected:
                    stream.write(f"# {email}\n")
                    for link in links:
                        stream.write(f"{link}\n")
                    stream.write("\n")
            total = sum(len(links) for _, links in collected)
            print(f"wrote {total} link(s) for {len(collected)} client(s) to {destination} (mode 600)")
            return 0

        if not args.to_stdout:
            for email, links in collected:
                print(f"{render.mask_label(email)}: {len(links)} link(s)")
            print("\nLinks are credentials. Use --out FILE to save them, or --print to show them.")
            return 0

        for email, links in collected:
            print(f"# {email}")
            for link in links:
                print(link)
            print()
        return 0

    print(f"unknown command: {args.command}")
    return 2
