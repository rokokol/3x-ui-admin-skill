# 3x-ui-admin-skill

Administer a [3x-ui](https://github.com/MHSanaei/3x-ui) panel from the command line,
over its HTTP API. Works as a plain CLI and as a Claude Code skill.

The panel's own web UI is fine for one change at a time. This exists for the rest:
auditing a configuration against the mistakes the API makes easy, editing objects
without silently resetting the fields you did not mention, checking that a
master-to-node link still authenticates what it claims to, and answering "which
client stopped connecting" without clicking through pages.

## Install

```sh
git clone https://github.com/rokokol/3x-ui-admin-skill
cd 3x-ui-admin-skill
mkdir -p secrets && chmod 700 secrets
printf 'https://panel.example:2053/your-secret-base-path' > secrets/url
printf '%s' 'YOUR_API_TOKEN' > secrets/token
chmod 600 secrets/url secrets/token
./xui inbound list
```

Create the token in the panel: **Settings → API tokens**, scope `admin`.

As a Claude Code skill, symlink or clone the directory into `~/.claude/skills/`.

Requires Python 3.11 or newer. No third-party packages.

## Configuration

| Source | URL | Token |
|---|---|---|
| flags | `--url` | `--token-file` |
| environment | `XUI_URL` | `XUI_TOKEN` |
| files | `secrets/url` | `secrets/token` |
| node registry | `panel` in `$XUI_NODES_DIR/<node>.toml` | `token` or `token_file` there |

`--node NAME` selects a node from the registry — a directory of one TOML per panel,
shared with whatever manages the machines. Registry files must not be readable
beyond their owner.

**The URL includes the base path.** The panel serves its API under the same secret
prefix as its UI, so `https://host:2053/abc123` is the address, not `https://host:2053`.

TLS verification is off by default because panels routinely present a certificate
for a name they are not reached by. Turn it on with `--verify-tls` when the
certificate does match.

## Usage

```sh
./xui nodes list                  # the master's view of its nodes
./xui nodes health                # status, heartbeat age, versions, load
./xui nodes link-check --require-private   # assert the link has not weakened

./xui inbound list                # id, protocol, port, traffic
./xui inbound get 1               # one inbound, credentials masked
./xui inbound settings 1          # stream settings, decoded from their JSON text

./xui client list                 # who exists, on which inbounds, with what flow
./xui client traffic --top 10     # heaviest users, with last-seen
./xui client idle --days 30       # who stopped connecting
./xui client orphans              # clients left behind by a deleted inbound
```

`--json` for scripting, `--reveal` to print credentials in full.

## Safety

Credentials are masked in every output by default. Client labels are partially
masked too: in a private fleet they hold real names.

Mutating commands read the object, write it back whole, read it again and diff —
because the panel's update endpoints replace rather than patch, so a field you omit
is a field you erase. Anything that can make the panel unreachable asks first.

## Licence

MIT.
