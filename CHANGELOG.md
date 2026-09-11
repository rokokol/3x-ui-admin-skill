# Changelog

Kept in the shape of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), dated rather than numbered, and with no `Unreleased` section — a skill is read at whatever revision you have checked out, so whatever is on the default branch is what every reader already has, and a section for work that has landed but not shipped would never close. The rule lives in the [versioning](https://github.com/rokokol/versioning-skill) skill, which owns what has no version

## 2026-09-11

### Changed

- SKILL.md, README.md and docs/*.md drop the trailing full stop from every prose paragraph, list item and table cell, and every hard-wrapped paragraph in SKILL.md now sits on one physical line
- SKILL.md's frontmatter description labels its trigger phrases "Triggers:" instead of "Триггеры:"
- SKILL.md's exit-code table gets a row for 130, which `xui` returns on Ctrl-C
- `.claude-plugin/plugin.json` drops its "version" key, since nothing bumped it and Claude Code versions a plugin by commit when the manifest carries none
- the build workflow runs the ci skill's `check-skill.sh` and the versioning skill's `check-changelog.sh`, vendored through the cascade, so `SKILL.md` has to load and its links resolve, and this changelog has to keep its shape; the repository had no skill check before

## 2026-09-10

### Changed

- `check-pins.sh` is vendored from the [ci](https://github.com/rokokol/ci-skill) skill through `vendor-sync.sh` and `.github/vendor.lock` instead of kept by hand, and a weekly cascade refreshes it, verifies the bump through this repository's own build workflow, and lands it only on green
- the vendored `vendor-sync.sh` and `vendor-sync.yml` are refreshed to the ci skill's current templates

## 2026-09-07

### Fixed

- the build workflow's pin guard is `check-pins.sh`, copied verbatim from the ci skill, instead of an inline grep that had drifted from the family's other copies and covered only some of the unpinned-lookup shapes
- the panel-URL gate's reserved-hostname allowlist includes `.invalid` beside `.example`, which RFC 2606 reserves the same way and which the allowlist had been missing

## 2026-09-03

### Added

- `routing test`, which asks the running core's own router through `RoutingService.TestRoute` whether a probe resolves to the outbound it should, and exits 1 on a miss
- `routing snapshot` and `routing restore`, a mode-600 dump of the whole routing template and its rollback
- `--node NAME` also works without a registry entry, from `secrets/url.NAME` + `secrets/token.NAME` beside the default pair

### Changed

- `--require-private` (was `--tailnet`) matches any private range — RFC 1918, the carrier-grade range, loopback, link-local — not only one fleet's tunnel, and narrows with a CIDR
- the range `routing check` may require blocked is `--require-blocked CIDR`, repeatable, instead of the tailnet-flavoured `--tailnet`
- docs/recovery.md says to look for the installer's token in `/etc/x-ui/install-result.env` before minting a replacement, since minting rotates the token and revokes every other holder
- the README shows a node registry file in one block instead of scattering its fields across three paragraphs

### Removed

- `pyrightconfig.json`, since pyright resolves `lib` from the project root without it, and `reportMissingImports=false` was hiding exactly the errors a type checker exists to raise

### Fixed

- `routing check` fails a rule naming no outbound wherever it sits, not only next to a private-range rule
- the registry example in the README uses RFC 5737 documentation space instead of live CGNAT space, which the secret gate exists to keep out of docs

## 2026-09-02

### Added

- a lint job running ruff and pyright in CI, pinned to the versions a developer runs locally
- `--pin-sha256` (also `secrets/pin`, `XUI_PIN_SHA256`, or a node's `pin_sha256`) and `./xui panel cert`, to pin and print a panel's certificate fingerprint
- `--allow-plaintext`, required before the token is sent over a plain `http://` URL to anything but loopback

### Changed

- credential masking and the database scrub share one list of credential-shaped keys instead of two that could drift, and the mask shows a sixth of a value's length instead of a fixed slice that gave away two thirds of a short password
- the database scrub's column lists match the real schema (WireGuard keys under `wg_private_key`, an external link's `value`, the `users` and `outbound_subscriptions` tables, a node's `base_path`) and are checked three ways: the known columns, every credential value searched for in the copy's bytes, and any cell shaped like a key or UUID
- redirects are never followed, and `--node NAME` takes its URL and token only from that node, never from an exported `XUI_URL`
- a `routing check` rule sending `geoip:private` to a chosen outbound is a note rather than a failure; only a missing reference or one naming no outbound still fails
- the hand-picked ruff rule set is dropped for the pinned version's own defaults, which is what the local build had actually been running
- the README is rewritten with a badge row, a Contents block, and the partial-update trap raised to a callout at the top

### Fixed

- a negative `expiryTime` no longer reads as an already-expired client
- `routing check` no longer requires a redundant tailnet rule where `geoip:private` already covers the carrier-grade range
- `sub links -o` tightens an existing file to mode 600 instead of leaving its prior mode in place, and refuses a symlink
- a heartbeat arriving as an RFC 3339 string no longer breaks `nodes health`
- a client label containing `?` or `#` no longer addresses the wrong resource, now that every path segment is quoted

## 2026-09-01

### Added

- `tests/no-secrets.sh`, a gate that greps tracked files for key material, the panel's session cookie, a literal token assignment, and a database or `secrets/` file
- a CI build workflow running the unit tests, the falsification harness and the secret gate on every push

### Changed

- the integration suite against a real panel in Docker moves off pull requests to push, a weekly cron and manual dispatch, with its actions pinned and a guard that fails the build on an unpinned registry lookup

## 2026-08-31

### Added

- the skill itself: `xui`, talking to a 3x-ui panel over `/panel/api` with a bearer token, and `SKILL.md`
- snapshot, change, verify on every mutation — read the object, apply the change, write it back whole, read it again, diff, and roll back what moved without being asked to
- `db pull`, sanitising a database export by default, with `--with-secrets` for a live copy
- `routing show` and `routing check`, catching a domain-and-ip rule that matches nothing, an `api` rule shadowed by the private block, a missing carrier-grade range, a rule naming no outbound, and a local rule below a transit one
- `sub` commands treating a subscription link as the credential it is, and `inbound validate` for stream-setting keys the panel stores but never applies
- `docs/recovery.md`, `docs/recipes.md`, `tests/integration.py` against a real panel in Docker, and `tests/falsify.py`, which edits one line of the implementation at a time and requires the suite to notice

### Fixed

- credentials are masked on the way out by default, with client labels degraded to a recognisable stub rather than to nothing
- `db pull`'s scrub is verified by a second, independent pass and refuses to write a copy where anything credential-shaped survives — the first version reported success while WAL mode left the edits uncommitted
