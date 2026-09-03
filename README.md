<div align="center">

# 3x-ui admin skill

**Administer a 3x-ui panel from the command line, without erasing what you did not mention (๑•̀ㅂ•́)و**

![Claude Code](https://img.shields.io/badge/Claude_Code-D97757?style=flat&logo=anthropic&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=flat&logo=python&logoColor=white)
![no dependencies](https://img.shields.io/badge/dependencies-none-3DA639?style=flat)
[![license](https://img.shields.io/badge/MIT-3DA639?style=flat)](LICENSE)
[![build](https://github.com/rokokol/3x-ui-admin-skill/actions/workflows/build.yml/badge.svg)](https://github.com/rokokol/3x-ui-admin-skill/actions/workflows/build.yml)
[![integration](https://github.com/rokokol/3x-ui-admin-skill/actions/workflows/integration.yml/badge.svg)](https://github.com/rokokol/3x-ui-admin-skill/actions/workflows/integration.yml)

</div>

The [3x-ui](https://github.com/MHSanaei/3x-ui) web UI is fine for one change at a time. This is for the rest: editing an object without silently resetting the fields you left out, auditing a configuration against the mistakes its API makes easy, checking that a master-to-node link still authenticates what it claims to, and answering "which client stopped connecting" without clicking through pages

It runs as a plain CLI and as a Claude Code skill from the same directory — `./xui` for a human, [SKILL.md](SKILL.md) for the agent, one implementation underneath

> [!IMPORTANT]
> The panel's update endpoints **replace** rather than patch, so a field you omit is a field you erase. Every mutating command here reads the object, writes it back whole, reads it again and diffs — and rolls back if anything moved that was not asked for

## Contents

- [Setup](#setup)
- [Configuration](#configuration)
- [Usage](#usage)
- [Safety](#safety)
- [Tests](#tests)
- [What this cannot do](#what-this-cannot-do)

## Setup

Python 3.11 or newer and nothing else — no third-party packages. Create the token in the panel under **Settings → API tokens** with scope `admin` — or, on a panel that was installed unattended, take the one the installer left in `/etc/x-ui/install-result.env` (see [recovery](docs/recovery.md#you-lost-the-api-token)) — then:

```bash
git clone https://github.com/rokokol/3x-ui-admin-skill
cd 3x-ui-admin-skill
mkdir -p secrets && chmod 700 secrets
printf 'https://panel.example:2053/your-secret-base-path' > secrets/url
printf '%s' 'YOUR_API_TOKEN' > secrets/token
chmod 600 secrets/url secrets/token
./xui inbound list
```

As a Claude Code skill, clone or symlink the directory into `~/.claude/skills/`, or take it as a plugin:

```
/plugin marketplace add rokokol/3x-ui-admin-skill
/plugin install 3x-ui-admin@rokokol-skills
```

## Configuration

| Source | URL | Token | Certificate pin |
| --- | --- | --- | --- |
| flags | `--url` | `--token-file` | `--pin-sha256` |
| environment | `XUI_URL` | `XUI_TOKEN` | `XUI_PIN_SHA256` |
| files | `secrets/url` | `secrets/token` | `secrets/pin` |
| node registry | `panel` in `$XUI_NODES_DIR/<node>.toml` | `token` or `token_file` there | `pin_sha256` there |

`--node NAME` selects another panel. The simplest form needs no registry: `secrets/url.NAME` and `secrets/token.NAME` beside the default pair. The registry — `$XUI_NODES_DIR`, one TOML per panel, shareable with whatever manages the machines — is for a fleet, and its files must not be readable beyond their owner. A node's URL and token come from the node and nowhere else (its TOML, or `secrets/url.NAME` and `secrets/token.NAME`): an `XUI_URL` left exported in the shell cannot pair the node's token with some other panel's address. Explicit flags still win

The URL includes the base path: the panel serves its API under the same secret prefix as its UI, so the address looks like `https://host:2053/abc123`

TLS verification is off by default because panels routinely present a certificate for a name they are not reached by. That leaves the link authenticated by nothing, so there are two ways to make it mean something: `--verify-tls` once the certificate does match, or a pin. `./xui panel cert` prints the sha256 of the certificate the panel presents; put it in `secrets/pin` (or `pin_sha256` in the node's TOML) and every later connection is refused unless the certificate matches it

A registry file holds, per panel, everything the table above lists plus the two switches; only `panel` is required, and a missing token falls back to `secrets/token.NAME`:

```toml
# $XUI_NODES_DIR/se-1.toml, mode 600
panel = "https://192.0.2.9:2053/abc123"
token_file = "~/.secrets/se-1.token"   # or token = "…"
pin_sha256 = "3f2a…"                    # optional, from: ./xui panel cert
verify_tls = false                      # optional
allow_plaintext = false                 # optional
```

A plain `http://` URL to anything but loopback is refused, because the token would travel in clear text. `--allow-plaintext` (or `allow_plaintext = true` in a node's TOML) overrides that for a network you trust, such as a tunnel. Redirects are never followed

## Usage

```bash
./xui nodes list                           # the master's view of its nodes
./xui nodes health                         # status, heartbeat age, versions, load
./xui nodes link-check --require-private   # assert the link has not weakened (or --require-private CIDR)

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
./xui routing check --require-blocked 203.0.113.0/24  # a range geoip:private does not cover
./xui routing test ifconfig.me=blocked github.com=direct  # what the running core would do
./xui routing snapshot xray.json           # the whole template, mode 600, for rollback
./xui routing restore xray.json --i-understand
./xui sub settings                         # where subscriptions are served
./xui sub check                            # is the subscription service coherent
./xui sub links -o links.txt               # export links to a 0600 file
./xui db pull                              # sanitised copy of the database

./xui panel list sub                       # settings matching a pattern
./xui panel get subPath                    # one setting, with its consequences
./xui panel set subTitle='My VPN'
./xui panel cert                           # sha256 of the certificate the panel presents
```

Add `--json` for machine-readable output and `--reveal` to print credentials in full; both are accepted anywhere on the line. Worked sequences for the common jobs live in [docs/recipes.md](docs/recipes.md)

## Safety

Credentials are masked in every output by default — at most a sixth of a value shows, so a UUID keeps a recognisable prefix while a short password shows one character — and client labels are partially masked because in a private fleet they hold real names. Inline TLS keys and the `pass` of a socks or http account are credentials too, whatever the panel calls them

The sanitised database copy is checked three ways before it is written: the columns the scrub knows about must be empty, every credential value read out of the original must be absent from the bytes of the copy, and no cell anywhere may still have the shape of a key. A copy that fails any of these is not written

When a rollback cannot restore a field, that is stated rather than glossed over. Settings that break already-distributed subscription links, or that can leave the panel unreachable, require `--i-understand`

## Tests

```bash
python3 -m unittest discover -s tests    # offline, no panel needed
python3 tests/integration.py             # against a real panel in a container
python3 tests/falsify.py                 # break each guard, require the tests to notice
tests/no-secrets.sh                      # nothing credential-shaped is tracked
ruff check . && pyright                  # the lint job, same pinned versions as CI
```

The falsification harness edits one line of the implementation at a time — removes the verification step, blinds a check, skips the scrub — and reruns the suite. A defect reported as `SURVIVED` means nothing fails when that behaviour is broken, which is the only honest way to know the tests are worth running. It found two blind spots on its first run: the sanitiser's journal-mode fix and masking, neither of which had a test at all

The integration suite starts a throwaway 3x-ui in docker, mints a token inside it and exercises the real thing — it corrupts a client with a partial update to prove the guard is needed, then repeats the edit through the guard to prove it works. It skips itself with a message when docker is unavailable

## What this cannot do

Bootstrap a panel, reset a forgotten password or 2FA, mint a replacement token after losing the current one, place certificate files on disk, or recover from a `webListen` pointing somewhere unreachable. The API has no endpoint for any of it, so the skill refuses rather than pretending — [docs/recovery.md](docs/recovery.md) says what to run over SSH instead
