#!/usr/bin/env python3
"""Rent a cairn seed on the smallest Runpod CPU pod, or refuse to.

No GPU flags are sent. After Runpod answers, the pod is deleted if the
quote is above CAIRN_SEED_MAX_USD_PER_HOUR (default $0.10), if a volume
appeared, or if the machine is not a CPU. A volume left behind keeps
billing after the compute stops; the request sets volumeInGb to 0 and
the response is what gets believed.

The pod's env receives DNS tokens and not RUNPOD_API_KEY. Printing a pod
object would print those tokens, so the only thing written to stdout is
public_summary plus the dial hint.

Usage:
  python3 create.py --dry-run
  python3 create.py              # create, or describe cairn-seed if it exists
  python3 create.py --status
  python3 create.py --down --yes
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import ddns  # noqa: E402
import spec  # noqa: E402

API = "https://rest.runpod.io/v1"
OUT = Path(__file__).resolve().parent / "out"
# apt, the release tarball, and the first identity write. Past this the
# pod is still billing and the summary says so; it is not deleted, because
# a slow pull is not a wrong machine.
WAIT_SECONDS = 480


class ApiError(RuntimeError):
    pass


def _api(method: str, path: str, token: str, body: dict | None = None):
    data = None if body is None else json.dumps(body).encode()
    request = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "cairn-seed-create",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            raw = response.read()
            if not raw:
                return None
            return json.loads(raw.decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read()[:500]
        raise ApiError(f"{method} {path} -> {exc.code}: {detail!r}") from exc


def _pods(token: str) -> list:
    payload = _api("GET", "/pods", token)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("pods") or []
    return []


def find_named(pods: list, name: str) -> dict | None:
    live = [pod for pod in pods if pod.get("name") == name and pod.get("desiredStatus") != "TERMINATED"]
    return live[0] if live else None


def mapped_port(pod: dict, internal: str) -> str | None:
    mappings = pod.get("portMappings") or {}
    for key in (internal, f"{internal}/tcp"):
        if key in mappings and mappings[key]:
            return str(mappings[key])
    return None


def _get(url: str, timeout: float = 10) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "cairn-seed-create"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_key(ip: str, port: str) -> tuple[str, bytes]:
    """Download the public key and check it against its own name.

    The filename is sha256 of the bytes the hex decodes to. A file that
    fails that is not this seed's key, whatever the directory listing said.
    """
    base = f"http://{ip}:{port}"
    entry = _get(f"{base}/entry.txt").decode()
    transport = ""
    for line in entry.splitlines():
        if line.startswith("transport="):
            transport = line.split("=", 1)[1].strip()
    if len(transport) != 64:
        raise RuntimeError(f"entry.txt has no transport id: {entry!r}")
    text = _get(f"{base}/{transport}.key").decode().strip()
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise RuntimeError("key file is not hex") from exc
    # Same derivation as crypto::kem::key_id: the id is not sha256 of the
    # raw key. Hashing the bytes alone rejects a key cairn itself published.
    digest = hashlib.sha256(b"proofwork/p2p/peer-id/v1" + raw).hexdigest()
    if digest != transport:
        raise RuntimeError(f"key id is {digest}, file is named {transport}")
    return transport, text.encode() + b"\n"


def hint(pod: dict, environ: dict) -> dict:
    ip = pod.get("publicIp") or ""
    host = ddns.dial_host(environ) or ip
    p2p = mapped_port(pod, "9000")
    http = mapped_port(pod, "8080")
    key = mapped_port(pod, "8090")
    return {
        "host": host,
        "ip": ip,
        "p2p": f"{host}:{p2p}" if host and p2p else None,
        "http": f"http://{host}:{http}" if host and http else None,
        "key": f"http://{ip}:{key}/entry.txt" if ip and key else None,
        "monthly_if_left_running": None
        if pod.get("costPerHr") is None
        else round(float(pod["costPerHr"]) * 730, 2),
    }


def _delete(token: str, pod_id: str) -> None:
    _api("DELETE", f"/pods/{pod_id}", token)


def _load(token: str, pod_id: str) -> dict:
    try:
        loaded = _api("GET", f"/pods/{pod_id}", token) or {}
        if isinstance(loaded, dict) and (loaded.get("id") or loaded.get("publicIp") or loaded.get("desiredStatus")):
            return loaded
    except ApiError as exc:
        print(f"cairn-seed: {exc}", file=sys.stderr)
    for pod in _pods(token):
        if pod.get("id") == pod_id:
            return pod
    return {}


def _reject_if_needed(token: str, pod: dict) -> None:
    """Delete a pod this process must not keep.

    A missing price is not a reason yet: the quote shows up when the
    machine is assigned. A GPU or a volume is a reason immediately,
    because those are visible on the create response and they bill.
    """
    pod_id = pod.get("id")
    reason = spec.unacceptable(pod, spec.max_usd_per_hour(os.environ))
    if reason is None or not pod_id:
        return
    priced = pod.get("costPerHr") is not None
    structural = not str(reason).startswith("costPerHr")
    if not structural and not priced:
        return
    print(f"cairn-seed: deleting {pod_id}: {reason}", file=sys.stderr)
    _delete(token, pod_id)
    raise SystemExit(3)


def _wait(token: str, pod_id: str) -> dict:
    deadline = time.time() + WAIT_SECONDS
    last = {}
    while time.time() < deadline:
        last = _load(token, pod_id)
        _reject_if_needed(token, last)
        if last.get("publicIp") and mapped_port(last, "9000") and mapped_port(last, "8080"):
            return last
        time.sleep(5)
    print(
        f"cairn-seed: {pod_id} has no public ports after {WAIT_SECONDS}s. "
        "It may still be billing. Delete it with: python3 launch/runpod-seed/down.sh",
        file=sys.stderr,
    )
    return last


def _require_token() -> str:
    token = os.environ.get("RUNPOD_API_KEY", "").strip()
    if not token:
        raise SystemExit(
            "RUNPOD_API_KEY is not set. Create one at "
            "https://console.runpod.io/user/settings and export it. "
            "Nothing was rented."
        )
    return token


def create(environ: dict | None = None) -> dict:
    environ = os.environ if environ is None else environ
    token = _require_token()
    body = spec.pod_body(environ)
    name = body["name"]
    existing = find_named(_pods(token), name)
    if existing:
        if str(existing.get("computeType") or "").upper() not in ("", "CPU"):
            raise SystemExit(
                f"{name} already exists and computeType is {existing.get('computeType')!r}. "
                "Refusing to reuse a GPU pod. Set CAIRN_SEED_NAME to rent a different one."
            )
        print(f"cairn-seed: {name} already exists ({existing.get('id')}); not renting another", file=sys.stderr)
        pod = existing
    else:
        created = _api("POST", "/pods", token, body)
        pod_id = created.get("id") if isinstance(created, dict) else None
        if not pod_id:
            raise SystemExit(f"create returned no id: {list((created or {}))[:8]}")
        print(f"cairn-seed: created {pod_id}", file=sys.stderr)
        _reject_if_needed(token, created)
        pod = _wait(token, pod_id)
    summary = spec.public_summary(pod)
    summary["hint"] = hint(pod, environ)
    _try_key(summary)
    return summary


def _try_key(summary: dict) -> None:
    hint_info = summary.get("hint") or {}
    url = hint_info.get("key")
    if not url or not summary.get("publicIp"):
        return
    port = mapped_port({"portMappings": summary.get("portMappings") or {}}, "8090")
    if not port:
        return
    deadline = time.time() + 180
    last = "not tried"
    while time.time() < deadline:
        try:
            health_port = mapped_port({"portMappings": summary.get("portMappings") or {}}, "8080")
            if health_port:
                health = _get(f"http://{summary['publicIp']}:{health_port}/health", timeout=5)
                if health.strip() != b"ok":
                    last = f"health {health[:40]!r}"
                    time.sleep(5)
                    continue
            transport, key = fetch_key(summary["publicIp"], port)
        except (urllib.error.URLError, RuntimeError, TimeoutError) as exc:
            last = str(exc)
            time.sleep(5)
            continue
        OUT.mkdir(mode=0o700, exist_ok=True)
        key_path = OUT / f"{transport}.key"
        key_path.write_bytes(key)
        fragment = {
            "name": "runpod-cpu",
            "addr": hint_info.get("p2p"),
            "transport": transport,
            "http": hint_info.get("http"),
            "operator": "the repository maintainer",
            "note": (
                "CPU pod rented by launch/runpod-seed. The addr is a hostname "
                "when dynamic DNS is configured, and a raw IP otherwise. The "
                "raw IP goes stale when the pod moves; re-run create.py --status "
                "and update this entry. The key file is the sha256 of its bytes."
            ),
        }
        (OUT / "seeds-entry.json").write_text(json.dumps(fragment, indent=2) + "\n")
        summary["key_file"] = str(key_path)
        summary["seeds_entry"] = fragment
        return
    print(f"cairn-seed: health or key not fetched yet ({last})", file=sys.stderr)


def down(yes: bool) -> None:
    if not yes:
        raise SystemExit("refusing to delete without --yes")
    token = _require_token()
    name = os.environ.get("CAIRN_SEED_NAME", spec.POD_NAME).strip() or spec.POD_NAME
    pod = find_named(_pods(token), name)
    if pod is None:
        print(f"cairn-seed: no pod named {name}")
        return
    _delete(token, pod["id"])
    print(f"cairn-seed: deleted {pod['id']} ({name})")


def main(argv: list[str]) -> int:
    if "--dry-run" in argv:
        body = spec.pod_body(dict(os.environ))
        # The boot scripts are not a secret, but they dominate the JSON and
        # hide the shape. Dry-run replaces them with their lengths.
        env = dict(body["env"])
        for key in ("CAIRN_BOOT_B64", "CAIRN_DDNS_B64"):
            env[key] = f"<{len(env[key])} chars>"
        # Dry-run is meant to be pasted into a ticket. The tokens that
        # would be sent to the pod are not.
        for key in ("DUCKDNS_TOKEN", "CF_API_TOKEN", "BUNNY_ACCESS_KEY", "DDNS_UPDATE_URL"):
            if key in env:
                env[key] = "REDACTED"
        body["env"] = env
        print(json.dumps(body, indent=2, sort_keys=True))
        return 0
    if "--down" in argv:
        down("--yes" in argv)
        return 0
    if "--status" in argv:
        token = _require_token()
        name = os.environ.get("CAIRN_SEED_NAME", spec.POD_NAME).strip() or spec.POD_NAME
        pod = find_named(_pods(token), name)
        if pod is None:
            print(f"cairn-seed: no pod named {name}")
            return 1
        summary = spec.public_summary(pod)
        summary["hint"] = hint(pod, os.environ)
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0
    summary = create()
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ApiError as exc:
        print(f"cairn-seed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
