"""Command groups. Each module exposes `help`, `register(parser)` and `run(args, client)`."""

from __future__ import annotations

from . import client as client_group
from . import inbound as inbound_group
from . import nodes as nodes_group

GROUPS = {
    "nodes": nodes_group,
    "inbound": inbound_group,
    "client": client_group,
}
