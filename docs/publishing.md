# Publishing a node

Everything else in this repository assumes the person reading the node is
either sitting at the machine or on its LAN. [serving.md](serving.md) ends
with "put a reverse proxy in front of it", [two-nodes.md](two-nodes.md) ends
with two routers, and neither says what an operator who owns neither a domain
nor a public IP is supposed to do. This page is that answer, with Tailscale,
because it was verified working on a real node rather than argued for.

The recipe assumes the node is already running:

```sh
cairn run --listen 0.0.0.0:9000 --serve 127.0.0.1:8080
```

`--listen 0.0.0.0` is the half that matters here: the p2p port binds the
wildcard, so a tailnet peer can dial it directly at the node's Tailscale IP
with no proxying at all. `--serve 127.0.0.1:8080` keeps HTTP on loopback,
which is where the next step wants it.

## Install and sign in

[Tailscale](https://tailscale.com) is a wireguard mesh with identity bolted
on: sign in, and every device on the same tailnet can reach every other by
name. The free tier is enough for one node and the handful of machines and
phones that read it.

```sh
curl -fsSL https://tailscale.com/install.sh | sh
tailscale up
```

`tailscale status` names this machine's MagicDNS name —
`your-host.tailnet-name.ts.net` — and its Tailscale IP. Both work as dial
targets; the name survives a restart that moves the IP, which is the same
reason [p2p.md](p2p.md) prefers a DNS name in a bootstrap file.

## HTTPS on the tailnet

The node's HTTP API and the reader terminate no TLS ([serving.md](serving.md),
"Not TLS"). Keeping `--serve` on loopback is deliberate here: Tailscale is
what answers on the tailnet (and, with funnel, on the open internet), so the
node itself never listens past this machine. A fleet that wants plaintext HTTP
on the WireGuard mesh without TLS termination uses `--serve tailnet:PORT`
instead — that path is [fleet.md](fleet.md#over-a-tailnet), not this recipe.

Tailscale terminates TLS for the loopback listener in one command:

```sh
tailscale serve --bg --https=8443 http://127.0.0.1:8080
```

After that, anything on your tailnet reaches the node at

- `https://your-host.tailnet-name.ts.net:8443/objectives` — the API
- `https://your-host.tailnet-name.ts.net:8443/ui/` — the reader

The certificate is issued for the MagicDNS name, so no browser warnings and no
reverse proxy to configure. Note that HTTPS also re-enables the clipboard on
these origins, which plain-HTTP serving on a LAN IP does not — the reader's
copy buttons degrade on insecure origins by design.

## Public, over the internet

Funnel is the same serve command, but forwarded from Tailscale's relay
infrastructure so that the open internet — anybody, not just your tailnet —
can reach the node:

```sh
tailscale funnel --https=8443 --bg http://127.0.0.1:8080
```

The URL is the same `https://your-host.tailnet-name.ts.net:8443`. Verify it
took with `tailscale funnel status`; that also shows how many of the funnel's
concurrent-connection limits you are using.

Funnel publishes the same ports serve does, so run one or the other on 8443,
not both — the second command replaces the first's route.

**A footgun, because it is silent.** `tailscale funnel --bg 8443` — a bare
number where the target goes — treats that number as a *backend port on this
machine*, not as the funnel's listening port. It can clobber other routes and
answer nothing. Always use the `--https=PORT` flag plus the full backend URL,
exactly as spelled above.

What the public gets is the same read-only API and reader. Writes are still
gated the way [serving.md](serving.md) describes: `POST /submit` is refused
when addressed to a public DNS name unless the operator lists it in
`CAIRN_HTTP_HOSTS`, and an operator exposing a node this way should read that
section before enabling queues.

## Peers over the tailnet

The p2p port needs none of this. `--listen 0.0.0.0:9000` binds the wildcard,
so a peer on the tailnet dials the node's Tailscale IP directly:

```sh
tailscale status --json   # "Self" carries this node's Tailscale IP
```

Put `<tailscale-ip>:9000` — or the MagicDNS name and port, which survives the
IP moving — in the peer record or bootstrap file, exactly as
[p2p.md](p2p.md) describes for any other address. A bootstrap address is only
a dial hint; the handshake decides who answered, so a tailnet name is no less
trustworthy than an IP. Two nodes on one tailnet therefore sync with no
port forwarding, no reverse proxy, and no seed file between them.

Funneling port 9000 to strangers is possible (`tailscale funnel --https=…`
is not the only shape) but is not what this recipe does: the p2p transport
authenticates by key and encrypts every frame already
([p2p.md](p2p.md), "What is encrypted"), and tailnet peers reach it
point-to-point without relay. What a stranger on the internet needs is the
*HTTP* half, which is what serve and funnel above publish.
