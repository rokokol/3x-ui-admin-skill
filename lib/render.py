"""Human-readable output, with credentials masked by default.

Panel objects carry the credentials that grant access to the VPN itself:
client UUIDs and passwords, Reality and WireGuard private keys, subscription
ids, inline TLS keys. Printing one into a terminal puts it into scrollback,
shell history and any transcript of the session, so masking is the default and
revealing is an explicit choice.
"""

from __future__ import annotations

import json
from typing import Any

# Kept as names so existing imports and tests keep working.
from .secret_keys import (  # noqa: F401
    PERSONAL_KEYS_EXACT,
    SECRET_KEY_PARTS,
    SECRET_KEYS_EXACT,
    holds_secret,
    is_personal,
    is_secret,
)

_is_secret = is_secret


def mask(value: Any) -> str:
    """A stub that identifies a value without giving much of it away.

    The reveal is proportional: a sixth of the length, rounded down. A UUID
    shows six characters, which is enough to tell two apart; a nine-character
    password shows one. The old fixed prefix of four plus a suffix of two gave
    away two thirds of a short password.
    """
    if isinstance(value, list):
        return f"[{len(value)} line(s), masked]"
    text = str(value)
    if not text:
        return ""
    if len(text) <= 8:
        return "***"
    keep = len(text) // 6
    return f"{text[:keep]}… ({len(text)} chars)"


def mask_label(value: Any) -> str:
    """Mask a name while keeping rows distinguishable.

    A client label is personal data but also the only handle an operator has on
    a row, so it degrades to a recognisable stub rather than to nothing.
    """
    text = str(value or "")
    if len(text) <= 2:
        return "*" * len(text)
    keep = 2 if len(text) <= 5 else 3
    return f"{text[:keep]}{'*' * (len(text) - keep)}"


def redact(obj: Any, reveal: bool = False, mask_personal: bool = True) -> Any:
    """Return a copy with credentials replaced by fingerprints."""
    if reveal:
        return obj
    if isinstance(obj, dict):
        out = {}
        for key, value in obj.items():
            if is_secret(key) and holds_secret(value):
                out[key] = mask(value)
            elif mask_personal and is_personal(key) and isinstance(value, str):
                # A label is masked to a stub, not to a fingerprint: it is
                # personal data, but it is also how the operator finds the row.
                out[key] = mask_label(value)
            else:
                out[key] = redact(value, reveal, mask_personal)
        return out
    if isinstance(obj, list):
        return [redact(item, reveal, mask_personal) for item in obj]
    if isinstance(obj, str):
        # Inbound settings arrive as a JSON string; redact inside it too, or the
        # keys would print in full through a field named `settings`.
        stripped = obj.strip()
        if stripped.startswith(("{", "[")) and len(stripped) > 2:
            try:
                inner = json.loads(stripped)
            except json.JSONDecodeError:
                return obj
            return redact(inner, reveal, mask_personal)
    return obj


def dumps(obj: Any, reveal: bool = False) -> str:
    return json.dumps(redact(obj, reveal), indent=2, ensure_ascii=False, default=str)


def table(rows: list[dict], columns: list[str]) -> str:
    """A plain aligned table. Values are stringified as-is; redact first."""
    if not rows:
        return "(nothing)"
    widths = {c: len(c) for c in columns}
    cells = []
    for row in rows:
        cell = {c: ("" if row.get(c) is None else str(row.get(c))) for c in columns}
        for c in columns:
            widths[c] = max(widths[c], len(cell[c]))
        cells.append(cell)
    header = "  ".join(c.ljust(widths[c]) for c in columns)
    divider = "  ".join("-" * widths[c] for c in columns)
    body = "\n".join("  ".join(cell[c].ljust(widths[c]) for c in columns) for cell in cells)
    return f"{header}\n{divider}\n{body}"


def human_bytes(count: Any) -> str:
    try:
        value = float(count or 0)
    except (TypeError, ValueError):
        return str(count)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"
