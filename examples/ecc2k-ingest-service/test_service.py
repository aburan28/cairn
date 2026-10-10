import importlib.util
import io
import json
import os
import sys
import tempfile
import types
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import service


class ServiceReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.key = Ed25519PrivateKey.generate()
        self.key_path = self.root / "auditor.pem"
        self.key_path.write_bytes(self.key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        ).hex()
        service.objective(SimpleNamespace(
            auditor_public_key=self.public, service="ecc2k130-dp-ingest-v1",
            input_bucket="example-private-dp",
            period_seconds=3600, unit_price=17, periods=3, funder="treasury",
            goal="GOAL-certicom-ecc2k130", created_at="2026-10-10T00:00:00Z",
            out_dir=self.root,
        ))
        spec = importlib.util.spec_from_file_location("checker", self.root / "checker.py")
        self.checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checker)

    def receipt(self, period=500000):
        def ts(t):
            return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        before = {"campaign_id": "ecc2k-130", "generated_at": ts(period * 3600),
                  "published_at": ts(period * 3600), "dps": 100,
                  "ingest": {"outstanding_objects": 0, "unrecognised_objects": 0}}
        after = {"campaign_id": "ecc2k-130", "generated_at": ts((period + 1) * 3600),
                 "published_at": ts((period + 1) * 3600), "dps": 101,
                 "ingest": {"outstanding_objects": 0, "unrecognised_objects": 0}}
        def snap(value):
            raw = json.dumps(value, sort_keys=True) + "\n"
            import hashlib
            return {"raw": raw, "sha256": hashlib.sha256(raw.encode()).hexdigest()}
        body = {
            "service": "ecc2k130-dp-ingest-v1", "input_bucket": "example-private-dp", "period": period,
            "operator": "ingester-operator", "nonce": "ab" * 32,
            "polls": 5,
            "input_objects": [{"key": "dp/example.bin", "sha256": "cd" * 32, "bytes": 64, "records": 2}],
            "progress": [{"key": "dp/example.bin", "records": 2, "duplicates": 1}],
            "before_status": snap(before), "after_status": snap(after),
        }
        return {"body": body, "period": period,
                "signature": self.key.sign(service.DOMAIN + service.canonical(body)).hex()}

    def test_valid_and_idle_period(self):
        receipt = self.receipt()
        self.assertTrue(self.checker.check(receipt)[0])
        receipt["body"]["input_objects"] = []
        receipt["body"]["progress"] = []
        receipt["signature"] = self.key.sign(
            service.DOMAIN + service.canonical(receipt["body"])).hex()
        self.assertTrue(self.checker.check(receipt)[0])

    def test_tampering_and_invalid_period(self):
        receipt = self.receipt()
        receipt["body"]["polls"] = 6
        self.assertFalse(self.checker.check(receipt)[0])
        receipt = self.receipt()
        receipt["period"] += 1
        self.assertFalse(self.checker.check(receipt)[0])
        receipt = self.receipt()
        receipt["body"]["progress"][0]["records"] += 1
        receipt["signature"] = self.key.sign(
            service.DOMAIN + service.canonical(receipt["body"])).hex()
        self.assertFalse(self.checker.check(receipt)[0])
        receipt = self.receipt()
        receipt["body"]["after_status"]["raw"] = receipt["body"]["after_status"]["raw"].replace('"dps": 101', '"dps": 999')
        receipt["signature"] = self.key.sign(
            service.DOMAIN + service.canonical(receipt["body"])).hex()
        self.assertEqual(self.checker.check(receipt)[1], "status bytes")

    def test_objective_pins_checker_and_price(self):
        import hashlib
        objective = json.loads((self.root / "objective.json").read_text())
        self.assertEqual(objective["reward"], 51)
        self.assertEqual(objective["piecework"], {"key": "period", "unit_price": 17})
        self.assertEqual(objective["verifier"]["checker_sha256"],
                         hashlib.sha256((self.root / "checker.py").read_bytes()).hexdigest())
        self.assertEqual(service.auditor_public_key(self.key_path), self.public)

    def test_rfc8032_known_signature(self):
        # Independent RFC 8032 test vector 1, not a sign/verify round trip.
        self.checker.AUDITOR_KEY = bytes.fromhex(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        signature = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
        self.assertTrue(self.checker.verify_signature(signature, b""))
        self.assertFalse(self.checker.verify_signature(signature, b"changed"))

    def test_collector_hashes_committed_s3_bytes(self):
        payload = bytes(range(64))

        class Cursor:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def execute(self, query, params):
                self_outer.assertEqual(params, ("ecc2k-130", "2026-10-10T00:00:00Z", "2026-10-10T01:00:00Z"))
                self_outer.assertIn("dp_ingest_progress", query)

            def fetchall(self):
                return [("dp/example.bin", 2, 1)]

        class Connection:
            def __enter__(self):
                return self

            def __exit__(self, *_):
                pass

            def cursor(self):
                return Cursor()

        self_outer = self
        s3 = types.SimpleNamespace(get_object=lambda **kw: {"Body": io.BytesIO(payload)})
        boto3 = types.SimpleNamespace(client=lambda name: s3)
        psycopg = types.SimpleNamespace(connect=lambda *_args, **_kwargs: Connection())
        args = SimpleNamespace(start="2026-10-10T00:00:00Z", end="2026-10-10T01:00:00Z", campaign="ecc2k-130",
                               bucket="private-bucket", max_objects=3,
                               objects_out=self.root / "objects.json",
                               progress_out=self.root / "progress.json")
        with patch.dict(sys.modules, {"boto3": boto3, "psycopg": psycopg}), \
             patch.dict(os.environ, {"DATABASE_URL": "postgresql://private"}):
            service.collect(args)
        import hashlib
        objects = json.loads(args.objects_out.read_text())
        progress = json.loads(args.progress_out.read_text())
        self.assertEqual(objects[0]["sha256"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(progress, [{"key": "dp/example.bin", "records": 2, "duplicates": 1}])

    def test_capture_preserves_exact_public_status_bytes(self):
        raw = self.receipt()["body"]["after_status"]["raw"].encode()
        source = self.root / "status.json"
        output = self.root / "captured.json"
        source.write_bytes(raw)
        service.capture(SimpleNamespace(url=source.as_uri(), out=output))
        self.assertEqual(output.read_bytes(), raw)


if __name__ == "__main__":
    unittest.main()
