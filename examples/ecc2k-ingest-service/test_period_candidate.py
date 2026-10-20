"""Exercise unsigned candidate assembly without cloud credentials."""

import hashlib
import importlib.util
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import period_candidate
import service


class FakeS3:
    def __init__(self, objects):
        self.objects = objects

    def get_object(self, Bucket, Key):
        return {"Body": io.BytesIO(self.objects[Key]), "VersionId": "v1"}


class CandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.period = int(time.time()) // 60 - 2
        start, end = self.period * 60, (self.period + 1) * 60
        before = {"campaign_id": "ecc2k-130", "dps": 123,
                  "generated_at": period_candidate.iso(start),
                  "published_at": period_candidate.iso(start),
                  "ingest": {"outstanding_objects": 0, "unrecognised_objects": 0}}
        after = before | {"dps": 124, "generated_at": period_candidate.iso(end),
                          "published_at": period_candidate.iso(end)}
        self.before_raw, self.after_raw = (service.canonical(value) + b"\n"
                                           for value in (before, after))
        before_digest = hashlib.sha256(self.before_raw).hexdigest()
        after_digest = hashlib.sha256(self.after_raw).hexdigest()
        before_name, after_name = (f"status-{digest}.json"
                                   for digest in (before_digest, after_digest))
        self.journal = {"schema": "cairn-dp-operator-period-v2",
                        "replica_id": "ingest-a", "period": self.period,
                        "period_seconds": 60, "started_at": start + 1,
                        "ended_at": end + 1, "healthy_at_end": True,
                        "events": [{"at": start + 1, "continued_pid": 123}],
                        "snapshots": [
                            {"observed_at": at, "sha256": before_digest, "file": before_name,
                             "generated_at": before["generated_at"]}
                            for at in (start + 1, end + 1)]}
        self.next_journal = {
            "schema": self.journal["schema"], "replica_id": "ingest-a",
            "period": self.period + 1,
            "snapshots": [{"observed_at": end + 2, "sha256": after_digest,
                           "file": after_name, "generated_at": after["generated_at"]}]}
        self.prefix = "logs/rho-ingest-a/evidence/"
        self.objects = {self.prefix + before_name: self.before_raw,
                        self.prefix + after_name: self.after_raw}
        self.args = SimpleNamespace(bucket="private-source", evidence_prefix=self.prefix,
                                    replica_id="ingest-a", operator="ed25519:operator",
                                    service="ecc2k130-dp-ingest-v2", period_seconds=60,
                                    period=self.period, max_objects=100, max_polls=100,
                                    out_dir=self.root / "candidates")

    def s3(self):
        objects = self.objects | {
            self.prefix + f"period-{self.period}.json": service.canonical(self.journal) + b"\n",
            self.prefix + f"period-{self.period + 1}.json": service.canonical(self.next_journal) + b"\n"}
        return FakeS3(objects)

    def test_assembles_private_unsigned_candidate_with_exact_status_bytes(self):
        collected = {}
        def collect(args):
            collected["database_url"] = args.database_url
            service.write_json(args.objects_out, [])
            service.write_json(args.progress_out, [])
            service.write_json(args.polls_out, {
                "replica_id": "ingest-a", "start": self.period * 60,
                "end": (self.period + 1) * 60,
                "events": [{"completed_at": period_candidate.iso(self.period * 60 + 10),
                            "objects": 0, "rows_added": 0}]})

        with patch.object(service, "collect", collect):
            destination = period_candidate.assemble(
                self.args, self.s3(), database_url="postgresql://selected-auditor"
            )
        self.assertEqual(collected["database_url"], "postgresql://selected-auditor")
        body = service.load_json(destination / "body.json")
        candidate = service.load_json(destination / "candidate.json")
        self.assertEqual(body["before_status"]["raw"], self.before_raw.decode())
        self.assertEqual(body["after_status"]["raw"], self.after_raw.decode())
        self.assertEqual(candidate["journal_version_id"], "v1")
        self.assertEqual(candidate["after_journal_s3_key"],
                         self.prefix + f"period-{self.period + 1}.json")
        self.assertEqual(candidate["decision"], "unsigned; independent auditor review required")
        self.assertEqual(candidate["body_sha256"], hashlib.sha256(service.canonical(body)).hexdigest())
        self.assertFalse((destination / "receipt.json").exists())
        key = Ed25519PrivateKey.generate()
        key_path = self.root / "auditor.pem"
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
        objective_dir = self.root / "objective"
        service.objective(SimpleNamespace(
            service=self.args.service, input_bucket=self.args.bucket,
            period_seconds=60, unit_price=17, funded_replica_periods=2,
            funder="treasury", goal="GOAL-certicom-ecc2k130",
            created_at=period_candidate.iso(self.period * 60),
            auditor_public_key=service.auditor_public_key(key_path),
            out_dir=objective_dir))
        signed = self.root / "receipt.json"
        service.sign(SimpleNamespace(body=destination / "body.json",
                                     auditor_key=key_path, out=signed))
        spec = importlib.util.spec_from_file_location("pinned_candidate_checker",
                                                   objective_dir / "checker.py")
        checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(checker)
        self.assertTrue(checker.check(service.load_json(signed))[0])
        with patch.object(service, "collect", side_effect=AssertionError("re-collected")):
            self.assertEqual(period_candidate.assemble(self.args, self.s3()), destination)

    def test_restart_trace_is_refused_before_private_source_collection(self):
        self.journal["events"].append({"at": self.period * 60 + 20, "exit_code": 7})
        with patch.object(service, "collect", side_effect=AssertionError("reached RDS")):
            with self.assertRaises(period_candidate.IneligiblePeriod) as caught:
                period_candidate.assemble(self.args, self.s3())
        self.assertEqual(caught.exception.reason, "invalid_journal")
        self.assertIn("restart, error", str(caught.exception.__cause__))
        self.assertFalse(list((self.root / "candidates").glob("*/candidate.json")))

    def test_unversioned_evidence_cannot_become_a_candidate(self):
        class Unversioned(FakeS3):
            def get_object(self, Bucket, Key):
                result = super().get_object(Bucket, Key)
                result.pop("VersionId")
                return result

        with patch.object(service, "collect", side_effect=AssertionError("reached RDS")):
            with self.assertRaisesRegex(ValueError, "immutable version id"):
                period_candidate.assemble(self.args, Unversioned(self.s3().objects))

    def test_missing_boundary_status_is_recorded_without_a_candidate(self):
        self.next_journal["snapshots"][0]["generated_at"] = period_candidate.iso(
            self.period * 60)
        with patch.object(service, "collect", side_effect=AssertionError("reached RDS")):
            with self.assertRaises(period_candidate.IneligiblePeriod) as caught:
                period_candidate.assemble(self.args, self.s3())
        self.assertEqual(caught.exception.reason, "missing_after_status")
        marker = period_candidate.record_ineligible(self.args, caught.exception)
        record = service.load_json(marker)
        self.assertEqual(len(record["journals"]), 2)
        self.assertEqual(record["journals"][1]["version_id"], "v1")
        self.assertTrue(period_candidate.previously_ineligible(self.args))
        self.assertFalse(list((self.root / "candidates").glob("*/candidate.json")))

    def test_watcher_advances_past_a_recorded_ineligible_period(self):
        period_candidate.record_ineligible(self.args, period_candidate.IneligiblePeriod(
            "missing_after_status", [
                {"s3_key": self.prefix + f"period-{self.period}.json",
                 "sha256": "a" * 64, "version_id": "v1"},
                {"s3_key": self.prefix + f"period-{self.period + 1}.json",
                 "sha256": "b" * 64, "version_id": "v1"}]))
        attempted = []

        def assemble(args, database_url=None):
            attempted.append(args.period)
            return self.root / "candidate"

        argv = ["--bucket", self.args.bucket, "--evidence-prefix", self.prefix,
                "--replica-id", self.args.replica_id, "--operator", self.args.operator,
                "--period-seconds", "60", "--watch-from", str(self.period),
                "--out-dir", str(self.args.out_dir)]
        with patch.object(period_candidate, "assemble", side_effect=assemble), patch.object(
                period_candidate.time, "sleep", side_effect=StopIteration):
            with self.assertRaises(StopIteration):
                period_candidate.main(argv)
        self.assertEqual(attempted, [self.period + 1])


if __name__ == "__main__":
    unittest.main()
