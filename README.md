# 3x-ui-admin-skill

Administer a [3x-ui](https://github.com/MHSanaei/3x-ui) panel from the command line, over its HTTP API. Works as a plain CLI and as a Claude Code skill.

The panel's own web UI is fine for one change at a time. This exists for the rest: editing objects without silently resetting the fields you did not mention, auditing a configuration against the mistakes the API makes easy, checking that a master-to-node link still authenticates what it claims to, and answering "which client stopped connecting" without clicking through pages.

## Setup

Requires Python 3.11 or newer and nothing else — no third-party packages.

Create the token in the panel under **Settings → API tokens** with scope `admin`, then:

```bash
git clone https://github.com/rokokol/3x-ui-admin-skill
cd 3x-ui-admin-skill
mkdir -p secrets && chmod 700 secrets
printf 'https://panel.example:2053/your-secret-base-path' > secrets/url
printf '%s' 'YOUR_API_TOKEN' > secrets/token
chmod 600 secrets/url secrets/token
./xui inbound list
```

As a Claude Code skill, clone or symlink the directory into `~/.claude/skills/`.

## Configuration

| Source | URL | Token |
| --- | --- | --- |
| flags | `--url` | `--token-file` |
| environment | `XUI_URL` | `XUI_TOKEN` |
| files | `secrets/url` | `secrets/token` |
| node registry | `panel` in `$XUI_NODES_DIR/<node>.toml` | `token` or `token_file` there |

`--node NAME` selects a panel from the registry, a directory holding one TOML per node that can be shared with whatever manages the machines. Registry files must not be readable beyond their owner.

The URL includes the base path. The panel serves its API under the same secret prefix as its UI, so the address is `https://host:2053/abc123`.

TLS verification is off by default because panels routinely present a certificate for a name they are not reached by. Turn it on with `--verify-tls` when the certificate does match.

## Usage

```bash
./xui nodes list                           # the master's view of its nodes
./xui nodes health                         # status, heartbeat age, versions, load
./xui nodes link-check --require-private   # assert the link has not weakened

./xui inbound list                         # id, protocol, port, traffic
./xui inbound get 1                        # one inbound, credentials masked
./xui inbound settings 1                   # stream settings, decoded

./xui client list                          # who exists, where, with what flow
./xui client traffic --top 10              # heaviest users, with last-seen
./xui client idle --days 30                # who stopped connecting
./xui client orphans                       # left behind by a deleted inbound

./xui client-edit fields                   # what may be set, and what it means
./xui client-edit set alice totalGB=53687091200
./xui client-edit add bob --inbound 1 --flow xtls-rprx-vision
./xui client-edit del bob --yes

./xui inbound validate                     # settings stored but never applied
./xui routing show                         # the rule chain, in order
./xui routing check                        # failures that leave no trace
./xui sub settings                         # where subscriptions are served
./xui sub check                            # is the subscription service coherent
./xui sub links -o links.txt               # export links to a 0600 file
./xui db pull                              # sanitised copy of the database

./xui panel list sub                       # settings matching a pattern
./xui panel get subPath                    # one setting, with its consequences
./xui panel set subTitle='My VPN'
```

Add `--json` for machine-readable output and `--reveal` to print credentials in full.

## Safety

Credentials are masked in every output by default, and client labels are partially masked because in a private fleet they hold real names.

Mutating commands read the object, write it back whole, read it again and diff — because the panel's update endpoints replace rather than patch, so a field you omit is a field you erase. If the panel moves anything that was not asked for, the change is rolled back and reported. When rollback cannot restore a field, that is stated rather than glossed over.

Settings that break already-distributed subscription links, or that can leave the panel unreachable, require `--i-understand`.

## What this cannot do

Bootstrap a panel, reset a forgotten password or 2FA, mint a replacement token after losing the current one, place certificate files on disk, or recover from a `webListen` that points somewhere unreachable. The API has no endpoint for any of it, so the skill refuses rather than pretending; `docs/recovery.md` says what to run over SSH instead.

## Licence

MIT.
