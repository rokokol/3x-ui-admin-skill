# Recipes

Sequences where the order matters, or where the obvious way breaks something quietly.

## Change the subscription paths

The panel warns that `/sub/` and `/json/` are well-known, and it is right — but the warning understates why. The path is not a secret in itself; the problem is that the service confirms a correct guess. An existing path answers `404` with an empty body, while an unknown one answers `404` with the router's own `404 page not found`. A scanner that knows the hostname can therefore find the real path by trying, and a default path needs no trying at all.

The hostname is the first gate: with `subDomain` set, a request arriving with any other `Host` — including a bare address — is refused outright.

Changing the paths kills every link already distributed. Clients fail silently: they fetch, get a 404, and keep the profile they already have until someone notices. So do it in one sitting:

```sh
./xui sub links -o links-before.txt          # what people are using now
./xui panel set subPath=/9f2c1a/ subJsonPath=/7d4e8b/ --i-understand
./xui sub links -o links-after.txt           # what they must switch to
```

Then hand out the new links before anyone's client next refreshes. Both files are written 0600 and hold live credentials; delete them once distributed.

`subURI` must agree with `subPath`, or generated links point at a path the service does not serve. `sub check` compares them.

## Add a client to a Vision inbound

`clients/add` never sets a flow, and a VLESS Reality inbound with Vision needs one, so a client created without it connects to nothing:

```sh
./xui client-edit add alice --inbound 1 --flow xtls-rprx-vision
```

The command reads the client back and warns if the panel stored a different flow than requested — which happens when the inbound cannot carry one.

## Change one field on a client

Never send a partial update by hand. The endpoint replaces the record, so an update naming only the field you care about empties `flow` and sets `enable` to false. This is measured behaviour, not caution:

```sh
./xui client-edit set alice totalGB=53687091200
```

The command reads the whole object, changes one field, writes it back whole, reads it again and refuses if anything else moved.

## Retire a client

```sh
./xui client-edit del alice --yes
```

Deleting a client is clean: the traffic rows, IP records and attachments go with it. Pass `--keep-traffic` to keep the counters.

Deleting an *inbound* is not clean — its clients survive with no attachments:

```sh
./xui client orphans        # find them
```

## Move a WireGuard inbound's MTU

1420 survives most paths but not DS-Lite or 464XLAT on mobile networks, where 1380 does. This lives in the inbound's settings, and `inbound validate` reports an inbound with no MTU at all.

Tunnel addresses must be unique within one inbound: a peer is addressed by its tunnel IP, and a duplicate hands one client another's traffic. Across inbounds they may repeat — each WireGuard inbound builds its own network stack.

## Check a fleet after touching anything

```sh
./xui nodes link-check --require-private   # the master still trusts the right node
./xui routing check --direct-before to-se  # local rules still precede transit ones
./xui inbound validate                     # nothing stored-but-ignored
./xui sub check                            # subscriptions still coherent
```

None of these failures announce themselves in the panel: the configuration stays valid and the traffic goes somewhere else.

## Pin the panel's certificate

Verification off means the token goes to whoever answers on that address. A pin fixes that without needing a certificate that matches a name:

```sh
./xui panel cert                              # prints sha256:…, the certificate presented right now
printf '%s' '<the hex>' > secrets/pin && chmod 600 secrets/pin
./xui inbound list                            # refused from now on if the certificate changes
```

Take the fingerprint over a path you already trust — the first connection from the machine the panel was set up from, or out-of-band from the host with `openssl x509 -in cert.pem -noout -fingerprint -sha256`. A renewed certificate changes the fingerprint, so a renewal is followed by a new pin; the refusal message shows the fingerprint that was seen.

For a node in the registry, put `pin_sha256 = "…"` in its TOML instead.

## Take a copy of the database

```sh
./xui db pull                     # sanitised: safe to keep, safe to diff
./xui db pull --with-secrets      # a live copy of the fleet, treat accordingly
```

The sanitised copy keeps the schema, the row counts and the routing, and empties every credential. It is what you want for reading configuration or comparing two points in time. The full copy is what you want for restoring, and it holds every client credential, the Reality and WireGuard keys and the node tokens.

Note what a database copy does *not* contain: the certificate files themselves — the settings hold only paths to them — and anything outside the panel. A restore onto a fresh machine also preserves that machine's own host-bound settings by default, so the mTLS material of the old one does not come back with it.
