"""Which keys hold credentials, shared by the renderer and the database scrub.

Two lists that describe the same idea drift apart: the renderer learned about
one key and the scrub about another, and each was "complete" by its own tests.
One list, one definition, and a value that one side hides the other blanks.
"""

from __future__ import annotations

from typing import Any

# Substring match, case-insensitive: the panel spells the same idea as `subId`,
# `privateKey`, `password`, `Secret`, `tgBotToken` across different objects.
SECRET_KEY_PARTS = (
    "password",
    "secret",
    "privatekey",
    "publickey",
    "presharedkey",
    "token",
    "subid",
    "auth",
    "shortids",
    "uuid",
    "pem",
)

# Exact keys that are secret despite an innocuous name. `id` is a client's
# UUID inside inbound settings; `key` is an inline TLS private key; `pass` is
# how Xray spells a socks or http account's password.
SECRET_KEYS_EXACT = frozenset({"id", "pbk", "sid", "spx", "key", "pass"})

# `email` is a client's label, and in a private fleet it tends to hold real
# people's names. It is masked as personal data, not as a credential.
PERSONAL_KEYS_EXACT = frozenset({"email"})


def is_secret(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    lowered = key.lower()
    if lowered in SECRET_KEYS_EXACT:
        return True
    return any(part in lowered for part in SECRET_KEY_PARTS)


def is_personal(key: Any) -> bool:
    return isinstance(key, str) and key.lower() in PERSONAL_KEYS_EXACT


def holds_secret(value: Any) -> bool:
    """A value shape a credential arrives in: text, or a list of text lines.

    A PEM key is stored as a list of lines. Numbers are never credentials in
    this panel - a numeric `id` is a row key, not a UUID.
    """
    if isinstance(value, str):
        return bool(value)
    if isinstance(value, list):
        return bool(value) and all(isinstance(item, str) for item in value)
    return False
