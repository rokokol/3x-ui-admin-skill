# Recovery

Everything this skill does goes through the panel API. These are the situations where the API cannot help, because they are about regaining access to it. All of them need a shell on the host, and one of them needs the provider's console

## You lost the API token

Tokens are stored as a SHA-256 hash, so there is nothing to read back from the panel. Before minting one, look at what the installer left behind: a panel installed unattended (cloud-init, or the `skibidi-vpn` roles) writes the token it minted at install time to `/etc/x-ui/install-result.env`, mode 600, under `XUI_API_TOKEN`, next to the first username and password. If that token was never rotated, it is still the one the panel accepts:

```sh
sudo grep '^XUI_API_TOKEN=' /etc/x-ui/install-result.env
```

Only if there is no such file, or the value there is refused, mint a replacement on the host:

```sh
x-ui setting -getApiToken
```

This rotates a single named token rather than accumulating new ones, and prints the new value once. Put it in `secrets/token` immediately; it cannot be recovered a second time. Rotation is not free: whoever else held the previous token — another registry, a script on the host — is refused from that moment, so a token issued in the panel's UI under its own name is the better long-term choice, because nothing on the host rotates it

## You lost the panel password, or 2FA

```sh
x-ui setting -username <new> -password <new>
x-ui setting -resetTwoFactor
```

The API refuses both without the current credentials, which is why they are here rather than in a command

## The panel is unreachable after a settings change

`webListen`, `webPort` and `webBasePath` decide where the panel answers, and a syntactically valid value that the host cannot bind — or that the firewall drops — locks you out with no rollback. Set them back on the host:

```sh
x-ui setting -listenIP <address>
x-ui setting -port <port>
x-ui setting -webBasePath <path>
systemctl restart x-ui
```

If the address itself was wrong and SSH also rides that interface, this needs the provider's console rather than SSH

## The certificate paths point at nothing

The API sets certificate *paths*; it never carries the files. If `webCertFile` or `subCertFile` names a file that does not exist, the panel or the subscription service serves nothing over TLS. Put the files where the setting expects them, or point the setting at where they are, then restart

Renewal belongs to whatever issues the certificate — acme.sh or certbot on the host. A renewal hook that reloads only nginx will never reload the panel, so the panel keeps serving the expired certificate until it is restarted

## The master lost its node

If a node's `tls_verify_mode` is `pin` and the node's certificate changed for any reason — including a renewal to a perfectly valid one — the master refuses the connection and the node reads as offline. Either update the stored fingerprint or move the link to `mtls`

If the mode is `mtls` and the master was restarted without its CA in the system trust store, every node goes offline at once with `certificate signed by unknown authority`. Go reads the trust store at process start, so trusting the CA requires a restart to take effect

Recovering either means editing the node row on the master, which the API can do — the node does not have to be reachable for that

## Before switching a link to mTLS

The node's certificate must be valid for the address the master actually uses. A certificate carrying only a DNS name in its SAN fails when the master connects by address, with a message about the certificate not being valid for any name it wanted. Either issue the node's certificate with the address in the SAN, or make the master reach the node by a name that resolves to it — and check that it resolves from the master, not only from your workstation

Order matters, and getting it wrong takes every node offline simultaneously:

1. Issue node certificates from your CA, each carrying the address or name the master will use
2. Put the CA's public half into the master's system trust store
3. Restart the master, so it reads the new trust store
4. Install the certificates on the nodes and let them trust the CA for incoming clients
5. Only then set the mode to `mtls`

Keep console access for the duration. The node side is forgiving — it verifies a client certificate only if one is presented — but the master side is not
