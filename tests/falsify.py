"""Break each guard on purpose and require the tests to notice.

A passing suite proves the code works only if the suite would fail when the code
does not. This harness edits one line of the implementation at a time, reruns
the tests, and reports a defect as SURVIVED when they still pass — meaning the
behaviour that line implements is not actually covered.

    python3 tests/falsify.py            # all defects
    python3 tests/falsify.py snapshot   # only those matching a name

Each edit is undone in a finally block, and the file contents are restored from
memory rather than from git, so an interrupted run cannot leave a mutated
working tree behind.
"""

from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


@dataclass
class Defect:
    name: str
    file: str
    find: str
    replace: str
    # What the defect does to the system, in the terms an operator would care
    # about. If the tests survive it, this sentence describes what nobody checks.
    consequence: str


DEFECTS = [
    Defect(
        name="snapshot/no-verification",
        file="lib/snapshot.py",
        find="    unintended = diff(intended, actual, ignore=ignored | set(missing))",
        replace="    unintended = Diff()",
        consequence="a write that silently clears flow or disables a client is accepted",
    ),
    Defect(
        name="snapshot/no-missing-check",
        file="lib/snapshot.py",
        find="""    missing = [
        key
        for key, wanted in changes.items()
        if _normalise(actual.get(key)) != _normalise(wanted)
    ]""",
        replace="    missing = []",
        consequence="a panel that ignores the write is reported as success",
    ),
    Defect(
        name="snapshot/no-rollback",
        file="lib/snapshot.py",
        find="        write(original)",
        replace="        pass",
        consequence="a refused mutation leaves the object in the state the panel mangled",
    ),
    Defect(
        name="snapshot/json-blind",
        file="lib/snapshot.py",
        find="            return _normalise(json.loads(stripped))",
        replace="            return value",
        consequence="reserialised settings read as a change, so every edit looks unfaithful",
    ),
    Defect(
        name="inbound/quic-unchecked",
        file="lib/inbound_checks.py",
        find='            if "quic" not in overrides:',
        replace="            if False:",
        consequence="domain routing silently stops matching over HTTP/3 and nothing says so",
    ),
    Defect(
        name="inbound/wireguard-key-unchecked",
        file="lib/inbound_checks.py",
        find='        if not settings.get("secretKey"):',
        replace="        if False:",
        consequence="an inbound that makes Xray refuse the whole config passes validation",
    ),
    Defect(
        name="inbound/duplicate-peer-address",
        file="lib/inbound_checks.py",
        find="                if address in seen:",
        replace="                if False:",
        consequence="two peers share a tunnel address and one client gets another's traffic",
    ),
    Defect(
        name="inbound/misspelling-blind",
        file="lib/inbound_checks.py",
        find="            if key != correct and key.lower() == correct.lower():",
        replace="            if False:",
        consequence="minClient and finalMask are stored, served and ignored, unreported",
    ),
    Defect(
        name="routing/order-unchecked",
        file="lib/commands/routing.py",
        find="            if rule.get(\"outboundTag\") in LOCAL_TAGS:",
        replace="            if False:",
        consequence="a local rule below a transit rule never fires and traffic leaves the country",
    ),
    Defect(
        name="routing/and-semantics-unchecked",
        file="lib/commands/routing.py",
        find='        if rule.get("domain") and rule.get("ip"):',
        replace="        if False:",
        consequence="a rule naming both domain and ip matches nothing and looks correct",
    ),
    Defect(
        name="routing/tailnet-unchecked",
        file="lib/commands/routing.py",
        find="    elif not any(TAILNET in (r.get(\"ip\") or []) for r in private_rules):",
        replace="    elif False:",
        consequence="tunnel clients reach the panel over its tailnet address",
    ),
    Defect(
        name="routing/api-position-unchecked",
        file="lib/commands/routing.py",
        find="    elif api_index != 0:",
        replace="    elif False:",
        consequence="client stats and online status read as empty with no explanation",
    ),
    Defect(
        name="db/sanitise-does-nothing",
        file="lib/commands/db.py",
        find='                connection.execute(f"UPDATE {table} SET {column} = \'\'")',
        replace="                pass",
        consequence="a copy handed out as sanitised still carries every client credential",
    ),
    Defect(
        name="db/wal-not-checkpointed",
        file="lib/commands/db.py",
        find='        connection.execute("PRAGMA journal_mode = DELETE")',
        replace="        pass",
        consequence="the scrub is written to a side file and lost when the copy is moved",
    ),
    Defect(
        name="db/personal-tables-kept",
        file="lib/commands/db.py",
        find='                connection.execute(f"DELETE FROM {table}")',
        replace="                pass",
        consequence="the addresses every client connected from ship with the copy",
    ),
    Defect(
        name="render/no-masking",
        file="lib/render.py",
        find="            if _is_secret(key) and isinstance(value, (str, int)):",
        replace="            if False:",
        consequence="UUIDs, keys and subscription ids print in full into terminal scrollback",
    ),
]


def run_tests() -> tuple[bool, str]:
    result = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", "tests", "-p", "test_*.py"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    return result.returncode == 0, result.stderr.strip().splitlines()[-1] if result.stderr else ""


def main(argv: list[str]) -> int:
    wanted = argv[0] if argv else ""
    defects = [d for d in DEFECTS if wanted in d.name]
    if not defects:
        print(f"no defect matches {wanted!r}")
        return 2

    passing, _ = run_tests()
    if not passing:
        print("the suite is already failing; fix that before falsifying it")
        return 2

    survived: list[Defect] = []
    for defect in defects:
        path = ROOT / defect.file
        original = path.read_text()
        if defect.find not in original:
            print(f"STALE    {defect.name}: the line it edits is gone from {defect.file}")
            survived.append(defect)
            continue
        try:
            path.write_text(original.replace(defect.find, defect.replace, 1))
            caught, _ = run_tests()
            if caught:
                print(f"SURVIVED {defect.name}")
                print(f"         nothing fails, so nobody checks: {defect.consequence}")
                survived.append(defect)
            else:
                print(f"caught   {defect.name}")
        finally:
            path.write_text(original)

    print()
    if survived:
        print(f"{len(survived)} of {len(defects)} defects went unnoticed.")
        return 1
    print(f"all {len(defects)} defects were caught by the tests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
