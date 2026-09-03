---
name: 3x-ui-admin
description: Administer a 3x-ui panel over its HTTP API — inbounds, clients, hosts, master/node links, routing, Xray and panel settings, subscriptions. Use when asked to inspect or change anything inside a 3x-ui panel, to audit a panel configuration for known footguns, or to work out why a client, subscription or node link stopped working. Триггеры: 3x-ui, x-ui, панель, инбаунд, клиент, подписка, нода, маршрутизация.
license: MIT
---

# 3x-ui admin

`./xui` talks to a 3x-ui panel through `/panel/api` with a bearer token. Everything the panel owns is reachable that way, so this skill carries no SSH; the few operations that genuinely need a shell are listed in `docs/recovery.md`.

## Access

Resolution order, first hit wins: command-line flags, `XUI_URL` / `XUI_TOKEN`, then `secrets/url` + `secrets/token`. With `--node NAME` the URL and token come only from that panel: `secrets/url.NAME` + `secrets/token.NAME`, or `panel`, `token` / `token_file` and `pin_sha256` in `$XUI_NODES_DIR/NAME.toml` for a fleet kept in a registry; the environment is ignored so one panel's token can never be sent to another's address. Never hardcode a token; never print one.

```bash
./xui inbound list                        # from secrets/
./xui --node se-1 nodes health            # secrets/url.se-1 + token.se-1, or $XUI_NODES_DIR/se-1.toml
XUI_URL=… XUI_TOKEN=… ./xui client list
```

The URL must include the panel's secret base path, because the API lives under it: `https://host:2053/abc123`, not `https://host:2053`. A 404 with an empty body means the base path is wrong or the token was refused — the two are indistinguishable from outside, and the client says so rather than guessing.

TLS verification is off by default because panels routinely present a certificate for a name they are not reached by. That authenticates nothing, so either turn verification on with `--verify-tls` when the certificate does match, or pin the certificate: `./xui panel cert` prints its sha256, and `--pin-sha256`, `secrets/pin` or `pin_sha256` in the node's TOML makes every connection check it. A plain `http://` URL to anything but loopback is refused unless `--allow-plaintext` is given, because the token would travel in clear text. Redirects are never followed.

## Common calls

```bash
./xui nodes health                        # status, heartbeat age, versions, load
./xui nodes link-check --require-private  # assert the link has not weakened
./xui inbound settings 1                  # stream settings, decoded from JSON text
./xui client traffic --top 10             # heaviest users, with last-seen
./xui client idle --days 30               # who stopped connecting
./xui client-edit set alice enable=false  # guarded edit
./xui panel list sub                      # every setting matching "sub"
./xui panel get subPath                   # one setting, with its consequences
./xui panel cert                          # certificate fingerprint, for pinning
./xui routing test ifconfig.me=blocked    # what the running core does, exit 1 on a miss
./xui routing snapshot xray.json          # whole template, mode 600, before an edit
```

`routing test` asks the core's own router through `RoutingService.TestRoute`: no traffic
is sent, and the answer is the decision the running config actually makes rather than the
one the rules appear to describe. Give each probe the outbound it must resolve to and the
command exits 1 when one lands elsewhere, so a probe list is a check that can go red. A
probe that matches no rule is reported against the node's first outbound, because that is
where the core sends it.

`--json` and `--reveal` are accepted anywhere on the line.

## Rules

Never print a credential. Client UUIDs and passwords, Reality and WireGuard keys, inline TLS keys, socks and http account passwords, subscription ids and tokens are masked by default; a mask shows at most a sixth of the value. `--reveal` is a deliberate choice and its output must not be pasted anywhere. Client labels are masked to a recognisable stub rather than to nothing: they are personal data, but they are also the only handle an operator has on a row.

Every mutation is snapshot, change, verify. Read the object, apply the change, write it back whole, read it again, diff. If anything moved that was not asked for, roll back from the snapshot and report. This is not a workaround for one bad field — the update endpoints replace rather than patch, so any field omitted from a write is a field erased.

An empty response body is a failure, never an empty result. The panel answers that way for a path it does not serve, so treating it as success reports work that never happened.

Say what a change breaks before making it. Changing a subscription path kills every distributed link; changing `webListen`, `webPort` or a certificate path can leave the panel unreachable with no way back through the API. Those keys require `--i-understand`.

Confirm destructive operations. Deleting a client removes its traffic history; deleting an inbound orphans its clients.

## What the panel gets wrong

`clients/add` takes `{"client": {…}, "inboundIds": [N]}` while `clients/update/{email}` takes a flat object. The hybrid shape is accepted and silently nulls every field not at the top level.

The panel does not answer in the shape it accepts. Reading a client returns a wrapper (`client`, `inboundIds`, `usedTraffic`, …); inside it `id` is the row's numeric key, while a write expects the client's UUID in that same field, and `allowedIPs` is read as a string but written as a list. Each mismatch is a hard type error, so a faithful round trip has to convert.

Measured on a live panel: an update carrying only `email`, `id` and one changed limit left the client with an empty flow and disabled. It still appeared in the UI; it simply could not connect.

`clients/add` never sets `flow`, so on a Vision inbound it must be passed explicitly. An omitted `enable` on update evaluates to false. `tgId` is an int64 and a string rejects the whole request.

The panel does not validate `flow` at all: it stores any string it is given, serves it, and the client fails to connect while the panel shows it as healthy. Measured against a real panel — the skill warns on a value Xray does not know, because nothing else will.

Creating a WireGuard inbound without a server key makes Xray reject the entire config and the node stops serving — generate the key first.

Deleting an inbound orphans its clients (`client orphans` finds them, `clients/delOrphans` removes them); deleting a client is clean.

`subId` is regenerated by two different code paths, and a new one invalidates every subscription link already handed out.

`tls_verify_mode: "verify"` verifies nothing — only `pin` and `mtls` authenticate the peer.

A routing-only save is applied through the core API without restarting it, and
`/usr/local/x-ui/bin/config.json` is **not** rewritten when that happens. The stored
template and the running core are the truth; that file catches up at the next start, so
auditing routing by reading it shows the state before the change.

A `geosite:`/`geoip:` reference to a category the `.dat` does not carry is stored without
complaint, matches nothing while it sits there, and stops the core at its next start.
`routing check` validates every reference the rules make, and says so when a panel is too
old to answer rather than passing quietly.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | done, or nothing to do |
| 1 | the panel refused, or a write was rolled back |
| 2 | bad usage, unknown key, or a guarded change without `--i-understand` |

## Caveats

Traffic counters live in a nested `traffic` object, not on the client itself, and they are cumulative since the last reset rather than per-period.

A client's `flow` is stored per inbound attachment; a read returns the derived value, so a client on both a Vision and a WebSocket inbound legitimately shows one flow while carrying none on the second.

`client idle` reads `lastOnline`, which is only written while the panel is running. A node that was down looks like a quiet client.

A negative `expiryTime` is not an expired client: it is a duration that starts at the client's first connection, and the panel flips it to a timestamp then. `client list` shows it as "Nd after first use".

A client label may contain `?` and `#`; the panel accepts them. Every command escapes the label into the request path, so such a client can still be read, edited and deleted.

`db pull` refuses to write a copy that still holds anything credential-shaped, and says which cell. That is a report to file, not a copy to keep.
