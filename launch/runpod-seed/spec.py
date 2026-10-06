"""The Runpod create-pod body for a cairn seed.

A seed is one process, two listening ports, and a public key. A GPU pod
bills for a device this process never opens. The body below is the whole
of the "cheap" claim: CPU, two vCPUs, no volume, a small container disk,
and a cost cap applied by the caller after Runpod quotes a price.

`volumeInGb` is set to 0 on purpose. The API's default is 20, and a
volume keeps billing after the pod stops. Zero means a restart wipes the
container disk, including the node identity, so a restart is a new peer
and needs a new publish. That is cheaper than a disk that outlives the
pod, and it is the trade the README states.
"""

from __future__ import annotations

import base64
from pathlib import Path

# General-purpose first. Compute-optimized flavors cost more per vCPU and
# a seed does not saturate them. The list is a preference order, not a
# request for three machines.
CPU_FLAVORS = ["cpu3g", "cpu3c", "cpu5c"]

# Power of two, and the smallest the pod API documents. One vCPU is not
# in that contract.
VCPU_COUNT = 2

# Charged only while the pod runs. The musl release is tens of megabytes;
# 10 GB is the slack apt needs to fetch it, not a place to keep data.
CONTAINER_DISK_GB = 10

# Default refusal line. A 730-hour month at this rate is about $73.
# create.py deletes a pod whose quote is above it.
DEFAULT_MAX_USD_PER_HOUR = 0.10

POD_NAME = "cairn-seed"

# What the pod is allowed to learn. The Runpod API key is not on this
# list: the pod does not need to manage itself, and a key in its env is
# a key in the pod description.
FORWARDED_ENV = (
    "DUCKDNS_TOKEN",
    "DUCKDNS_SUBDOMAIN",
    "CF_API_TOKEN",
    "CF_ZONE_ID",
    "DDNS_HOST",
    "BUNNY_ACCESS_KEY",
    "BUNNY_ZONE_ID",
    "BUNNY_RECORD_NAME",
    "DDNS_UPDATE_URL",
    "CAIRN_VERSION",
    "CAIRN_HTTP_HOSTS",
    "DDNS_INTERVAL",
)

HERE = Path(__file__).resolve().parent

# Ports strangers use. 8090 serves only the public transport key, so the
# operator can fetch it without SSH. The identity file, which holds the
# secret, is a different directory and is not on this port.
PORTS = ["9000/tcp", "8080/tcp", "8090/tcp"]

START = r"""
set -eu
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq curl ca-certificates python3
python3 - <<'PY'
import base64, os, pathlib
pathlib.Path("/usr/local/bin/cairn-ddns.py").write_bytes(base64.b64decode(os.environ["CAIRN_DDNS_B64"]))
pathlib.Path("/tmp/cairn-boot.sh").write_bytes(base64.b64decode(os.environ["CAIRN_BOOT_B64"]))
os.chmod("/usr/local/bin/cairn-ddns.py", 0o755)
os.chmod("/tmp/cairn-boot.sh", 0o755)
PY
exec bash /tmp/cairn-boot.sh
""".strip()


def _b64_file(name: str) -> str:
    return base64.b64encode((HERE / name).read_bytes()).decode("ascii")


def _forwarded(environ: dict) -> dict:
    out = {}
    for key in FORWARDED_ENV:
        value = environ.get(key)
        if value is None:
            continue
        text = str(value).strip()
        if text:
            out[key] = text
    return out


def max_usd_per_hour(environ: dict) -> float:
    raw = str(environ.get("CAIRN_SEED_MAX_USD_PER_HOUR") or "").strip()
    if not raw:
        return DEFAULT_MAX_USD_PER_HOUR
    try:
        value = float(raw)
    except ValueError as exc:
        raise SystemExit(f"CAIRN_SEED_MAX_USD_PER_HOUR={raw!r} is not a number") from exc
    if value <= 0:
        raise SystemExit("CAIRN_SEED_MAX_USD_PER_HOUR must be greater than zero")
    return value


def over_cap(cost_per_hour, cap: float) -> bool:
    """True when Runpod has quoted a price this launcher must not keep.

    A missing quote is not under the cap. Treating 'unknown' as zero is
    how a GPU pod would survive the check that exists to refuse it.
    """
    if cost_per_hour is None:
        return True
    try:
        cost = float(cost_per_hour)
    except (TypeError, ValueError):
        return True
    return cost > cap


def pod_body(environ: dict | None = None) -> dict:
    environ = environ or {}
    name = str(environ.get("CAIRN_SEED_NAME") or POD_NAME).strip() or POD_NAME
    cloud = str(environ.get("CAIRN_SEED_CLOUD") or "COMMUNITY").strip().upper()
    if cloud not in ("COMMUNITY", "SECURE"):
        raise SystemExit("CAIRN_SEED_CLOUD must be COMMUNITY or SECURE")
    interruptible = str(environ.get("CAIRN_SEED_INTERRUPTIBLE") or "").strip().lower() in (
        "1",
        "true",
        "yes",
    )
    env = _forwarded(environ)
    env["CAIRN_DDNS_B64"] = _b64_file("ddns.py")
    env["CAIRN_BOOT_B64"] = _b64_file("boot.sh")
    return {
        "name": name,
        "computeType": "CPU",
        "cloudType": cloud,
        "imageName": "ubuntu:24.04",
        "containerDiskInGb": CONTAINER_DISK_GB,
        "volumeInGb": 0,
        "vcpuCount": VCPU_COUNT,
        "cpuFlavorIds": list(CPU_FLAVORS),
        "cpuFlavorPriority": "custom",
        "supportPublicIp": True,
        "interruptible": interruptible,
        "ports": list(PORTS),
        "dockerEntrypoint": ["bash", "-lc"],
        "dockerStartCmd": [START],
        "env": env,
    }


def public_summary(pod: dict) -> dict:
    """Fields safe to print. The pod env holds DNS tokens."""
    mappings = pod.get("portMappings") or {}
    return {
        "id": pod.get("id"),
        "name": pod.get("name"),
        "desiredStatus": pod.get("desiredStatus"),
        "computeType": pod.get("computeType"),
        "cpuFlavorId": pod.get("cpuFlavorId"),
        "vcpuCount": pod.get("vcpuCount"),
        "publicIp": pod.get("publicIp"),
        "portMappings": mappings,
        "costPerHr": pod.get("costPerHr"),
        "volumeInGb": pod.get("volumeInGb"),
        "containerDiskInGb": pod.get("containerDiskInGb"),
        "interruptible": pod.get("interruptible"),
    }


def unacceptable(pod: dict, cap: float) -> str | None:
    """Why a created pod must be deleted, or None to keep it.

    Checked on the response, not the request. A default that ignores a
    zero we sent — the 20 GB volume, a GPU — would bill for something
    this launcher claimed not to rent.
    """
    if str(pod.get("computeType") or "").upper() not in ("", "CPU"):
        return f"computeType is {pod.get('computeType')!r}, not CPU"
    volume = pod.get("volumeInGb")
    if volume not in (None, 0, 0.0):
        return f"volumeInGb is {volume}, not 0"
    if over_cap(pod.get("costPerHr"), cap):
        return f"costPerHr {pod.get('costPerHr')} is above the cap {cap}"
    return None
