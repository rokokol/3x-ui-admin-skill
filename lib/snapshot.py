"""Change an object without losing the fields you did not mention.

The panel's update endpoints replace rather than patch: a field absent from the
request becomes its zero value. `flow` empties, `enable` turns false, a limit
resets to unlimited. So a safe edit is never "send the change" — it is read the
whole object, modify a copy, send the whole copy back, read it again, and prove
that only the intended fields moved.

The verification half matters as much as the merge. The panel also normalises
some fields on write — regenerating a subscription id, dropping a flow the
inbound cannot carry — and those are exactly the changes nobody asked for.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class MutationError(Exception):
    """A write that did not land as intended. The object may have been rolled back."""


@dataclass
class Diff:
    changed: dict[str, tuple[Any, Any]] = field(default_factory=dict)

    def __bool__(self) -> bool:
        return bool(self.changed)

    def describe(self, mask: Callable[[str, Any], Any] | None = None) -> str:
        lines = []
        for key, (before, after) in sorted(self.changed.items()):
            if mask:
                before, after = mask(key, before), mask(key, after)
            lines.append(f"  {key}: {before!r} -> {after!r}")
        return "\n".join(lines)


def _normalise(value: Any) -> Any:
    """Compare by meaning, not by spelling.

    Sub-objects travel as JSON *text*, and the panel re-serialises them on every
    write: key order and whitespace change without anything meaningful changing.
    """
    if isinstance(value, str):
        stripped = value.strip()
        if stripped.startswith(("{", "[")):
            try:
                return _normalise(json.loads(stripped))
            except json.JSONDecodeError:
                return value
        return value
    if isinstance(value, dict):
        return {k: _normalise(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [_normalise(v) for v in value]
    return value


def diff(before: dict, after: dict, ignore: set[str] | None = None) -> Diff:
    """Fields whose meaning differs between two versions of an object."""
    ignore = ignore or set()
    result = Diff()
    for key in set(before) | set(after):
        if key in ignore:
            continue
        old, new = before.get(key), after.get(key)
        if _normalise(old) != _normalise(new):
            result.changed[key] = (old, new)
    return result


# Written on every save by the panel itself; a change here says nothing about
# whether the edit was faithful.
TIMESTAMP_FIELDS = {"updatedAt", "updated_at", "lastOnline", "last_online"}


def apply_and_verify(
    read: Callable[[], dict],
    write: Callable[[dict], Any],
    changes: dict[str, Any],
    ignore: set[str] | None = None,
) -> Diff:
    """Merge `changes` into the current object, write it, and prove the result.

    Returns the diff of what actually changed. Raises MutationError when the
    panel moved something that was not asked for, after attempting to restore
    the original.
    """
    original = read()
    if not isinstance(original, dict):
        raise MutationError("object to edit was not returned as a JSON object")

    intended = dict(original)
    intended.update(changes)

    write(intended)

    actual = read()
    ignored = (ignore or set()) | TIMESTAMP_FIELDS

    # Asked for but absent comes first: a panel that quietly kept its old value
    # is a different failure from one that moved something else, and reporting
    # it as the latter would send the reader looking in the wrong place.
    missing = [
        key
        for key, wanted in changes.items()
        if _normalise(actual.get(key)) != _normalise(wanted)
    ]
    unintended = diff(intended, actual, ignore=ignored | set(missing))

    if missing or unintended:
        reasons = []
        if missing:
            reasons.append(
                "the panel accepted the write but did not apply: "
                + ", ".join(sorted(missing))
            )
        if unintended:
            reasons.append(
                "the panel changed fields nobody asked for:\n" + unintended.describe()
            )
        raise MutationError("; ".join(reasons) + _restore(read, write, original, ignored))

    return diff(original, actual, ignore=ignored)


def _restore(
    read: Callable[[], dict],
    write: Callable[[dict], Any],
    original: dict,
    ignored: set[str],
) -> str:
    """Put the object back, and say plainly whether that worked.

    Rollback travels the same write path that just misbehaved, so a panel that
    always mangles a field will mangle it again here. Claiming a clean rollback
    in that case would be the more dangerous lie.
    """
    try:
        write(original)
    except Exception as error:  # noqa: BLE001 - the caller needs both failures
        return f"\nROLLBACK FAILED, object left as the panel wrote it: {error}"

    try:
        restored = read()
    except Exception as error:  # noqa: BLE001
        return f"\nrollback written but could not be verified: {error}"

    residue = diff(original, restored, ignore=ignored)
    if residue:
        return (
            "\nROLLBACK INCOMPLETE - the panel mangles these on every write, so they "
            "cannot be restored through the API:\n" + residue.describe()
        )
    return "\nrolled back"
