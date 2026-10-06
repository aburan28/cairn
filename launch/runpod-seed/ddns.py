#!/usr/bin/env python3
"""Point a hostname at this pod's current address.

The name is a dial hint. `launch/seeds.json` is compiled into the binary,
so an IP written there is stale the moment a community pod moves, and
every already-built node keeps dialing it. A hostname in that file does
not move. This script is what makes the name true.

Three providers, because the zone is whoever already has one:

* DuckDNS — a free name on somebody else's site (`<sub>.duckdns.org`).
* Cloudflare — a zone the operator owns. The record is created if it is
  missing. `proxied` is forced false: Cloudflare's proxy speaks HTTP and
  would answer the p2p port with a web error page.
* Bunny — the DNS API behind a zone hosted there. `aburan.com` is served
  by Convertri's nameservers, whose SOA is `hostmaster.bunny.net`, so
  this is the call that updates a name on that site once an API key exists.
* `DDNS_UPDATE_URL` — any other site, with the literal `{ip}` replaced.

No provider is "off". The seed still runs; newcomers then depend on the
raw IP, which this script says out loud each time it looks.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

IPIFY = "https://api.ipify.org"


def _env(environ: dict, key: str) -> str:
    return str(environ.get(key) or "").strip()


def valid_ipv4(text: str) -> bool:
    parts = text.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        number = int(part)
        if number > 255 or (part != "0" and part.startswith("0")):
            return False
    return True


def dial_host(environ: dict) -> str | None:
    """The name strangers should dial, when one is configured."""
    host = _env(environ, "DDNS_HOST")
    if host:
        return host
    sub = _env(environ, "DUCKDNS_SUBDOMAIN")
    if sub and _env(environ, "DUCKDNS_TOKEN"):
        return f"{sub}.duckdns.org"
    return None


def plans(ip: str, environ: dict) -> list[dict]:
    """HTTP calls that would make `ip` the address of the configured name.

    Tokens are in the plan. `redact` is what gets printed.
    """
    if not valid_ipv4(ip):
        raise ValueError(f"not an IPv4 address: {ip!r}")
    out: list[dict] = []
    sub = _env(environ, "DUCKDNS_SUBDOMAIN")
    token = _env(environ, "DUCKDNS_TOKEN")
    if sub or token:
        if not sub or not token:
            raise ValueError("DuckDNS needs both DUCKDNS_SUBDOMAIN and DUCKDNS_TOKEN")
        query = urllib.parse.urlencode({"domains": sub, "token": token, "ip": ip})
        out.append(
            {
                "provider": "duckdns",
                "method": "GET",
                "url": f"https://www.duckdns.org/update?{query}",
                "headers": {},
                "body": None,
            }
        )
    cf_token = _env(environ, "CF_API_TOKEN")
    zone = _env(environ, "CF_ZONE_ID")
    host = _env(environ, "DDNS_HOST")
    if cf_token or zone:
        if not cf_token or not zone or not host:
            raise ValueError("Cloudflare needs CF_API_TOKEN, CF_ZONE_ID, and DDNS_HOST")
        out.append(
            {
                "provider": "cloudflare",
                "method": "UPSERT",
                "url": f"https://api.cloudflare.com/client/v4/zones/{zone}/dns_records",
                "headers": {"Authorization": f"Bearer {cf_token}"},
                "body": {
                    "type": "A",
                    "name": host,
                    "content": ip,
                    "ttl": 60,
                    # The proxy is an HTTP middlebox. A p2p dial that lands
                    # on it fails in a way that looks like a dead seed.
                    "proxied": False,
                },
            }
        )
    bunny_key = _env(environ, "BUNNY_ACCESS_KEY")
    bunny_zone = _env(environ, "BUNNY_ZONE_ID")
    if bunny_key or bunny_zone:
        if not bunny_key or not bunny_zone or not host:
            raise ValueError("Bunny needs BUNNY_ACCESS_KEY, BUNNY_ZONE_ID, and DDNS_HOST")
        out.append(
            {
                "provider": "bunny",
                "method": "UPSERT",
                "url": f"https://api.bunny.net/dnszone/{bunny_zone}/records",
                "headers": {"AccessKey": bunny_key},
                "body": {
                    "Type": 0,
                    "Name": bunny_record_name(host, environ),
                    "Value": ip,
                    "Ttl": 60,
                },
            }
        )
    template = _env(environ, "DDNS_UPDATE_URL")
    if template:
        if "{ip}" not in template:
            raise ValueError("DDNS_UPDATE_URL must contain the literal {ip}")
        out.append(
            {
                "provider": "url",
                "method": "GET",
                "url": template.replace("{ip}", urllib.parse.quote(ip)),
                "headers": {},
                "body": None,
            }
        )
    return out


def bunny_record_name(host: str, environ: dict) -> str:
    """The label Bunny stores, which is not the FQDN.

    `seed.aburan.com` -> `seed`. Deeper names (`a.b.example.com`) are not
    guessed: the left-most label would be the wrong record.
    """
    explicit = _env(environ, "BUNNY_RECORD_NAME")
    if explicit:
        return explicit
    labels = host.split(".")
    if len(labels) != 3:
        raise ValueError(
            f"{host} has {len(labels)} labels; set BUNNY_RECORD_NAME to the "
            "record name inside the zone"
        )
    return labels[0]


# Printed by --dry-run. Anything else in the query string is treated as a
# credential: DuckDNS puts the token there, and so do most of the others.
_PUBLIC_QUERY = {"ip", "domains", "domain", "hostname", "addr", "name"}


def redact(plan: dict) -> dict:
    url = plan["url"]
    parsed = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query = [(key, value if key.lower() in _PUBLIC_QUERY else "REDACTED") for key, value in query]
    safe_url = urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )
    headers = {}
    for key, value in plan.get("headers", {}).items():
        if key.lower() in ("authorization", "accesskey"):
            headers[key] = "REDACTED"
        else:
            headers[key] = value
    return {
        "provider": plan["provider"],
        "method": plan["method"],
        "url": safe_url,
        "headers": headers,
        "body": plan.get("body"),
    }


def _request(method: str, url: str, headers: dict, body: dict | None, timeout: float = 20):
    data = None if body is None else json.dumps(body).encode()
    req_headers = {"Accept": "application/json", "User-Agent": "cairn-seed-ddns"}
    req_headers.update(headers)
    if data is not None:
        req_headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=req_headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read()
            return response.status, raw
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        raise RuntimeError(f"{method} {url.split('?')[0]} -> {exc.code}: {raw[:300]!r}") from exc


def _cloudflare(plan: dict) -> None:
    headers = plan["headers"]
    base = plan["url"]
    body = plan["body"]
    name = urllib.parse.quote(body["name"])
    status, raw = _request("GET", f"{base}?type=A&name={name}", headers, None)
    if status != 200:
        raise RuntimeError(f"cloudflare list -> {status}")
    payload = json.loads(raw.decode() or "{}")
    records = payload.get("result") or []
    if not records:
        _request("POST", base, headers, body)
        return
    record_id = records[0]["id"]
    _request("PUT", f"{base}/{record_id}", headers, body)


def _bunny(plan: dict) -> None:
    headers = plan["headers"]
    # .../dnszone/{id}/records -> zone url is that without /records
    records_url = plan["url"]
    zone_url = records_url[: -len("/records")]
    body = plan["body"]
    _status, raw = _request("GET", zone_url, headers, None)
    zone = json.loads(raw.decode() or "{}")
    existing = None
    for record in zone.get("Records") or []:
        if record.get("Type") == 0 and record.get("Name") == body["Name"]:
            existing = record
            break
    if existing is None:
        _request("POST", records_url, headers, body)
        return
    _request("POST", f"{records_url}/{existing['Id']}", headers, body)


def apply_plans(ip: str, environ: dict) -> list[dict]:
    made = plans(ip, environ)
    for plan in made:
        if plan["provider"] == "cloudflare":
            _cloudflare(plan)
        elif plan["provider"] == "bunny":
            _bunny(plan)
        else:
            _request(plan["method"], plan["url"], plan["headers"], plan["body"])
        print(f"cairn-seed: ddns updated {plan['provider']} -> {ip}", file=sys.stderr)
    if not made:
        print(
            "cairn-seed: no dynamic DNS configured; the published address is "
            "the raw IP and goes stale when the pod moves",
            file=sys.stderr,
        )
    return made


def current_ip(environ: dict | None = None) -> tuple[str | None, str]:
    """The inbound address, preferring the one Runpod published.

    ipify sees the outbound address. On a pod those can differ, and a
    dial to the outbound address is a timeout. The platform's value is
    the one in the connect dialog.
    """
    environ = environ if environ is not None else os.environ
    published = _env(environ, "RUNPOD_PUBLIC_IP")
    if valid_ipv4(published):
        return published, "RUNPOD_PUBLIC_IP"
    try:
        request = urllib.request.Request(IPIFY, headers={"User-Agent": "cairn-seed-ddns"})
        with urllib.request.urlopen(request, timeout=10) as response:
            text = response.read().decode().strip()
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"cairn-seed: ddns: ipify: {exc}", file=sys.stderr)
        return None, "none"
    if not valid_ipv4(text):
        print(f"cairn-seed: ddns: ipify returned {text!r}", file=sys.stderr)
        return None, "none"
    print(
        "cairn-seed: ddns: RUNPOD_PUBLIC_IP is unset; using the outbound "
        "address from ipify, which may not be the inbound one",
        file=sys.stderr,
    )
    return text, "ipify"


def watch(environ: dict) -> None:
    raw = _env(environ, "DDNS_INTERVAL") or "300"
    interval = int(raw)
    if interval < 30:
        raise SystemExit("DDNS_INTERVAL below 30s just hammers the DNS provider")
    last = None
    while True:
        try:
            ip, _source = current_ip(environ)
            if ip and ip != last:
                apply_plans(ip, environ)
                host = dial_host(environ) or ip
                p2p = _env(environ, "RUNPOD_TCP_PORT_9000") or "?"
                http = _env(environ, "RUNPOD_TCP_PORT_8080") or "?"
                print(
                    f"cairn-seed: dial-hint host={host} p2p_port={p2p} http_port={http} ip={ip}",
                    file=sys.stderr,
                )
                last = ip
        except Exception as exc:  # noqa: BLE001 — a DNS failure must not kill the seed
            print(f"cairn-seed: ddns: {exc}", file=sys.stderr)
            last = None
        time.sleep(interval)


def main(argv: list[str], environ: dict | None = None) -> int:
    environ = os.environ if environ is None else environ
    dry = "--dry-run" in argv
    ip = None
    if "--ip" in argv:
        ip = argv[argv.index("--ip") + 1]
    if ip is None and not dry:
        ip, _source = current_ip(environ)
    if dry:
        shown = ip or "203.0.113.10"
        for plan in plans(shown, environ):
            print(json.dumps(redact(plan), sort_keys=True))
        if not plans(shown, environ):
            print(json.dumps({"provider": None}))
        return 0
    if "--watch" in argv:
        watch(environ)
        return 0
    if not ip:
        print("cairn-seed: ddns: no address yet", file=sys.stderr)
        return 1
    apply_plans(ip, environ)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ValueError as exc:
        print(f"cairn-seed: ddns: {exc}", file=sys.stderr)
        raise SystemExit(2) from exc
