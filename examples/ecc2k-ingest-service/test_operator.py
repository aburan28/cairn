"""Exercise the real supervisor process without AWS or a database."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent


class OperatorTests(unittest.TestCase):
    def test_continuous_child_archives_a_period_and_stops(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "status.json"
            status.write_text(json.dumps({"campaign_id": "ecc2k-130", "dps": 3,
                                          "generated_at": "2026-10-17T10:00:00Z",
                                          "published_at": "2026-10-17T10:00:00Z"}))
            evidence = root / "evidence"
            result = subprocess.run(
                [sys.executable, str(HERE / "operator.py"),
                 "--replica-id", "ingest-a",
                 "--evidence-dir", str(evidence),
                 "--status-url", status.as_uri(),
                 "--period-seconds", "2", "--poll-seconds", "0.1",
                 "--max-periods", "1", "--", sys.executable,
                 "-c", "import time; time.sleep(20)"],
                capture_output=True, text=True, timeout=8)
            self.assertEqual(result.returncode, 0, result.stderr)
            periods = list(evidence.glob("period-*.json"))
            self.assertEqual(len(periods), 1)
            journal = json.loads(periods[0].read_text())
            self.assertEqual(journal["replica_id"], "ingest-a")
            self.assertTrue(any("started_pid" in event for event in journal["events"]))
            self.assertTrue(journal["healthy_at_end"])
            self.assertTrue(journal["snapshots"])
            self.assertEqual(len(list(evidence.glob("status-*.json"))), 1,
                             "repeated polls should not copy unchanged status bytes")

    def test_failed_child_is_recorded_before_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            status = root / "status.json"
            status.write_text('{"campaign_id":"ecc2k-130","dps":0}')
            evidence = root / "evidence"
            result = subprocess.run(
                [sys.executable, str(HERE / "operator.py"),
                 "--replica-id", "ingest-b",
                 "--evidence-dir", str(evidence), "--status-url", status.as_uri(),
                 "--period-seconds", "3", "--poll-seconds", "0.1",
                 "--restart-delay", "0.1", "--max-periods", "2", "--",
                 sys.executable, "-c", "import sys; sys.exit(7)"],
                capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            journals = [json.loads(path.read_text())
                        for path in evidence.glob("period-*.json")]
            events = [event for journal in journals for event in journal["events"]]
            self.assertTrue(any(event.get("exit_code") == 7 for event in events))
            self.assertGreaterEqual(sum("started_pid" in event for event in events), 2)


if __name__ == "__main__":
    unittest.main()
