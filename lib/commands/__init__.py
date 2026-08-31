"""Command groups. Each module exposes `help`, `register(parser)` and `run(args, client)`."""

from __future__ import annotations

from . import client as client_group
from . import client_edit as client_edit_group
from . import db as db_group
from . import inbound as inbound_group
from . import nodes as nodes_group
from . import panel as panel_group
from . import routing as routing_group
from . import sub as sub_group

GROUPS = {
    "nodes": nodes_group,
    "inbound": inbound_group,
    "client": client_group,
    "client-edit": client_edit_group,
    "panel": panel_group,
    "db": db_group,
    "routing": routing_group,
    "sub": sub_group,
}
