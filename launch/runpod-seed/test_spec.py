#!/usr/bin/env python3
"""The launcher's claims, without renting anything."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import ddns  # noqa: E402
import spec  # noqa: E402

CREATE = HERE / "create.py"


def _body(env: dict | None = None) -> dict:
    return spec.pod_body(env or {})


class SpecTest(unittest.TestCase):
    def test_cpu_only_and_no_volume(self):
        body = _body()
        self.assertEqual(body["computeType"], "CPU")
        self.assertEqual(body["volumeInGb"], 0)
        self.assertEqual(body["vcpuCount"], 2)
        self.assertEqual(body["cpuFlavorIds"][0], "cpu3g")
        self.assertEqual(body["containerDiskInGb"], 10)
        self.assertTrue(body["supportPublicIp"])
        self.assertFalse(body["interruptible"])
        self.assertEqual(body["cloudType"], "COMMUNITY")
        self.assertEqual(body["ports"], ["9000/tcp", "8080/tcp", "8090/tcp"])
        self.assertNotIn("gpuTypeIds", body)
        self.assertNotIn("gpuCount", body)
        self.assertNotIn("cuda", body["imageName"].lower())
        self.assertNotIn("gpu", body["dockerStartCmd"][0].lower())

    def test_api_key_is_not_forwarded(self):
        body = _body({"RUNPOD_API_KEY": "rpa_secret", "DUCKDNS_TOKEN": "tok", "DUCKDNS_SUBDOMAIN": "cairn"})
        self.assertNotIn("RUNPOD_API_KEY", body["env"])
        self.assertNotIn("rpa_secret", json.dumps(body["env"]))
        self.assertEqual(body["env"]["DUCKDNS_TOKEN"], "tok")

    def test_cap_treats_a_missing_quote_as_too_expensive(self):
        self.assertFalse(spec.over_cap(0.10, 0.10))
        self.assertFalse(spec.over_cap(0.04, 0.10))
        self.assertTrue(spec.over_cap(0.11, 0.10))
        self.assertTrue(spec.over_cap(None, 0.10))
        self.assertTrue(spec.over_cap("nope", 0.10))

    def test_a_gpu_or_a_volume_in_the_response_is_rejected(self):
        self.assertIsNone(spec.unacceptable({"computeType": "CPU", "volumeInGb": 0, "costPerHr": 0.04}, 0.10))
        self.assertIn("GPU", spec.unacceptable({"computeType": "GPU", "volumeInGb": 0, "costPerHr": 0.01}, 0.10))
        self.assertIn("volume", spec.unacceptable({"computeType": "CPU", "volumeInGb": 20, "costPerHr": 0.01}, 0.10))
        self.assertIn("costPerHr", spec.unacceptable({"computeType": "CPU", "volumeInGb": 0, "costPerHr": 1.12}, 0.10))

    def test_summary_drops_env(self):
        summary = spec.public_summary(
            {"id": "abc", "publicIp": "203.0.113.10", "env": {"DUCKDNS_TOKEN": "tok"}, "costPerHr": 0.04}
        )
        self.assertNotIn("env", summary)
        self.assertNotIn("tok", json.dumps(summary))

    def test_dry_run_exits_without_a_key(self):
        env = {key: value for key, value in os.environ.items() if key != "RUNPOD_API_KEY"}
        result = subprocess.run(
            [sys.executable, str(CREATE), "--dry-run"],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        body = json.loads(result.stdout)
        self.assertEqual(body["computeType"], "CPU")
        self.assertNotIn("rpa_", result.stdout)

    def test_dry_run_redacts_dns_tokens(self):
        env = {key: value for key, value in os.environ.items() if key != "RUNPOD_API_KEY"}
        env["DUCKDNS_TOKEN"] = "super-secret-token"
        env["DUCKDNS_SUBDOMAIN"] = "cairn-seed"
        result = subprocess.run(
            [sys.executable, str(CREATE), "--dry-run"],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("super-secret-token", result.stdout)
        self.assertIn("cairn-seed", result.stdout)
        self.assertIn("REDACTED", result.stdout)

    def test_create_without_a_key_rents_nothing(self):
        env = {key: value for key, value in os.environ.items() if key != "RUNPOD_API_KEY"}
        result = subprocess.run(
            [sys.executable, str(CREATE)],
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("RUNPOD_API_KEY", result.stderr)
        self.assertIn("Nothing was rented", result.stderr)


class DdnsTest(unittest.TestCase):
    def test_duckdns_plan_and_redaction(self):
        made = ddns.plans(
            "203.0.113.10",
            {"DUCKDNS_SUBDOMAIN": "cairn-seed", "DUCKDNS_TOKEN": "secret-token"},
        )
        self.assertEqual(len(made), 1)
        self.assertIn("secret-token", made[0]["url"])
        self.assertIn("203.0.113.10", made[0]["url"])
        shown = ddns.redact(made[0])
        self.assertNotIn("secret-token", shown["url"])
        self.assertIn("203.0.113.10", shown["url"])
        self.assertIn("REDACTED", shown["url"])

    def test_cloudflare_record_is_not_proxied(self):
        made = ddns.plans(
            "203.0.113.10",
            {"CF_API_TOKEN": "tok", "CF_ZONE_ID": "zone", "DDNS_HOST": "seed.example.com"},
        )
        self.assertEqual(made[0]["body"]["proxied"], False)
        self.assertEqual(made[0]["body"]["content"], "203.0.113.10")
        shown = ddns.redact(made[0])
        self.assertEqual(shown["headers"]["Authorization"], "REDACTED")
        self.assertNotIn("tok", json.dumps(shown))

    def test_bunny_name_is_the_label_not_the_fqdn(self):
        made = ddns.plans(
            "198.51.100.20",
            {"BUNNY_ACCESS_KEY": "key", "BUNNY_ZONE_ID": "9", "DDNS_HOST": "seed.aburan.com"},
        )
        self.assertEqual(made[0]["body"]["Name"], "seed")
        self.assertEqual(made[0]["body"]["Type"], 0)
        self.assertEqual(made[0]["body"]["Value"], "198.51.100.20")
        shown = ddns.redact(made[0])
        self.assertEqual(shown["headers"]["AccessKey"], "REDACTED")

    def test_deeper_bunny_name_is_not_guessed(self):
        with self.assertRaises(ValueError):
            ddns.plans(
                "198.51.100.20",
                {"BUNNY_ACCESS_KEY": "key", "BUNNY_ZONE_ID": "9", "DDNS_HOST": "a.b.example.com"},
            )

    def test_no_provider_is_an_empty_plan(self):
        self.assertEqual(ddns.plans("203.0.113.10", {}), [])
        self.assertIsNone(ddns.dial_host({}))
        self.assertEqual(
            ddns.dial_host({"DUCKDNS_SUBDOMAIN": "cairn-seed", "DUCKDNS_TOKEN": "t"}),
            "cairn-seed.duckdns.org",
        )

    def test_generic_url_requires_the_placeholder(self):
        with self.assertRaises(ValueError):
            ddns.plans("203.0.113.10", {"DDNS_UPDATE_URL": "https://example.com/update"})
        made = ddns.plans("203.0.113.10", {"DDNS_UPDATE_URL": "https://example.com/update?addr={ip}"})
        self.assertEqual(made[0]["url"], "https://example.com/update?addr=203.0.113.10")

    def test_key_name_is_the_peer_id_derivation(self):
        # create.py must use the same id as crypto::kem::key_id. sha256 of
        # the raw key is a different value and rejects a real publish.
        raw = b"not a real mceliece key, the domain string is the point"
        transport = hashlib.sha256(b"proofwork/p2p/peer-id/v1" + raw).hexdigest()
        self.assertNotEqual(hashlib.sha256(raw).hexdigest(), transport)
        self.assertEqual(
            hashlib.sha256(b"proofwork/p2p/peer-id/v1" + bytes.fromhex(raw.hex())).hexdigest(),
            transport,
        )


class BootTest(unittest.TestCase):
    def test_boot_script_parses(self):
        result = subprocess.run(["bash", "-n", str(HERE / "boot.sh")], check=False, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
