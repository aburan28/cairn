# Transport keys for the published seed list

One file per seed, named for the peer it belongs to:

```
<transport>.key    the hex McEliece transport public key, 522,240 characters
```

`<transport>` is the peer id, which **is** `sha256` of the bytes the file
decodes to. That is the whole security argument for publishing this directory
on GitHub Pages, or on any host nobody has to trust: `cairn seeds resolve`
re-derives the id from the bytes before it writes a bootstrap file, so a mirror
can withhold a key, or serve one that does not match its name, and both are
refused. What it cannot do is put a *different key under the same name*.

`tests/seeds_list.rs` checks that property over this directory, so the list this
repository publishes is only ever one that verifies.

## Adding your seed

On the seed host, against the identity the daemon persists:

```sh
cairn seeds publish --identity .local/node.identity.json --out launch/seeds/
```

It prints the entry to add to [`../seeds.json`](../seeds.json). Open a pull
request with both. There is no upload endpoint and there should not be:
publishing is a reviewed change to a repository, which is what makes this anchor
replaceable by somebody other than whoever holds the server.

The `addr` you publish is the one strangers can reach, not the one you pass to
`--listen`. A seed on a cloud instance binds `0.0.0.0` — its public address is
NAT'd to it and appears on no local interface — and publishes the public address
or, better, the public DNS name, which survives a restart that moves the IP.
See [docs/p2p.md](../../docs/p2p.md), *Running a seed on a public host*.

## Why the keys are not in `seeds.json`

522 KB each. `ui/lib/seeds.ts` fetches the list from the browser on every page
load to find a node to read, and an index that carried a megabyte of key
material the browser will never use would be paying for the p2p half of the file
on every visit. The list carries the id; the key is fetched only by the tool
that dials.
