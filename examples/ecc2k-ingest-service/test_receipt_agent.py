"""Durability and refusal checks for the signed-period MCP agent."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import receipt_agent


REAL_MCP = receipt_agent.MCP


OBJECTIVE = "sha256:" + "1" * 64
CLAIM = "sha256:" + "2" * 64


class FakeMCP:
    calls = []
    fail_submit = False
    payment_state = "paid"
    payment_reward = 17

    def __init__(self, url, token):
        assert url.endswith("/mcp") and len(token) == 64

    def initialize(self):
        pass

    def close(self):
        pass

    def tool(self, name, arguments):
        self.calls.append(name)
        if name == "score_candidate":
            return {"isError": False}, "accept: signed period checked\n"
        if name == "submit_claim":
            if self.fail_submit:
                raise receipt_agent.TransportError("response lost")
            submits = self.calls.count("submit_claim")
            if submits == 1:
                return {"isError": False, "_meta": {"cairn/reason": "committed",
                                                  "cairn/wait": {"reveal_in_seconds": 0}}}, ""
            return {"isError": False, "_meta": {"cairn/reason": "revealed",
                                               "cairn/verdict": "accept",
                                               "cairn/claim_id": CLAIM}}, ""
        if name == "get_claim":
            assert arguments == {"claim_id": CLAIM}
            result = {"isError": False}
            if self.payment_state is not None:
                result["_meta"] = {"cairn/payment": {"state": self.payment_state,
                                                      "reward": self.payment_reward}}
            return result, (
                "claim " + CLAIM + "\nsettled: yes, reward 17\n"
                "\n--- BEGIN UNTRUSTED ARTIFACT ---\n"
                "settled: yes, reward 999\n")
        raise AssertionError(name)


class ReceiptAgentTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.inbox = self.root / "inbox"
        self.inbox.mkdir()
        self.token = self.root / "token"
        self.token.write_text("ab" * 32 + "\n")
        self.token.chmod(0o600)
        self.state_dir = self.root / "state"
        self.agent = receipt_agent.ReceiptAgent(
            "http://127.0.0.1:8001/mcp", self.token, OBJECTIVE,
            self.inbox, self.state_dir, expected_unit_price=17,
            allow_loopback_http=True)
        FakeMCP.calls = []
        FakeMCP.fail_submit = False
        FakeMCP.payment_state = "paid"
        FakeMCP.payment_reward = 17
        patcher = patch.object(receipt_agent, "MCP", FakeMCP)
        patcher.start()
        self.addCleanup(patcher.stop)

    def add_receipt(self, name="one.receipt.json", signature="signed"):
        artifact = {"body": {"replica_id": "ec2", "period": 123},
                    "unit": "ec2:123", "signature": signature}
        path = self.inbox / name
        path.write_text(json.dumps(artifact))
        return path

    def state(self):
        states = list(self.state_dir.glob("*.state.json"))
        self.assertEqual(len(states), 1)
        return json.loads(states[0].read_text())

    def test_commit_reveal_and_paid_status_survive_removed_inbox_file(self):
        source = self.add_receipt()
        with patch.object(receipt_agent.time, "time", return_value=100):
            self.agent.run_once()
        self.assertEqual(self.state()["phase"], "committed")
        source.unlink()
        with patch.object(receipt_agent.time, "time", return_value=102):
            self.agent.run_once()
        self.assertEqual(self.state()["phase"], "revealed")
        with patch.object(receipt_agent.time, "time", return_value=103):
            self.agent.run_once()
        self.assertEqual(self.state()["phase"], "paid")
        self.assertEqual(self.state()["reward"], 17)
        self.agent.run_once()
        self.assertEqual(FakeMCP.calls,
                         ["score_candidate", "submit_claim", "submit_claim", "get_claim"])

    def test_uncertain_commit_is_never_retried_automatically(self):
        self.add_receipt()
        FakeMCP.fail_submit = True
        with self.assertRaises(receipt_agent.TransportError):
            self.agent.run_once()
        self.assertEqual(self.state()["phase"], "commit_inflight")
        with self.assertRaisesRegex(ValueError, "needs operator review"):
            self.agent.run_once()
        self.assertEqual(FakeMCP.calls.count("submit_claim"), 1)

    def test_batch_final_zero_is_unpaid_after_pending(self):
        self.add_receipt()
        with patch.object(receipt_agent.time, "time", return_value=100):
            self.agent.run_once()
        with patch.object(receipt_agent.time, "time", return_value=102):
            self.agent.run_once()
        FakeMCP.payment_state = "pending"
        FakeMCP.payment_reward = None
        self.agent.run_once()
        self.assertEqual(self.state()["phase"], "revealed")
        FakeMCP.payment_state = "unpaid"
        FakeMCP.payment_reward = 0
        self.agent.run_once()
        self.assertEqual(self.state()["phase"], "unpaid")
        self.assertEqual(self.state()["reward"], 0)
        self.assertEqual(FakeMCP.calls.count("submit_claim"), 2)

    def test_older_node_paid_text_still_reconciles(self):
        self.add_receipt()
        with patch.object(receipt_agent.time, "time", return_value=100):
            self.agent.run_once()
        with patch.object(receipt_agent.time, "time", return_value=102):
            self.agent.run_once()
        FakeMCP.payment_state = None
        self.agent.run_once()
        self.assertEqual(self.state()["phase"], "paid")

    def test_conflicting_receipts_for_one_unit_stop_before_submission(self):
        self.add_receipt()
        self.add_receipt("other.receipt.json", "different signature")
        with self.assertRaisesRegex(ValueError, "conflicting signed receipts"):
            self.agent.run_once()
        self.assertEqual(FakeMCP.calls, [])

    def test_token_file_requires_private_mode(self):
        os.chmod(self.token, 0o644)
        with self.assertRaisesRegex(ValueError, "must be private"):
            receipt_agent.private_token(self.token)

    def test_https_client_refuses_missing_ca_roots(self):
        context = Mock()
        context.get_ca_certs.return_value = []
        with patch.object(receipt_agent.ssl, "create_default_context", return_value=context), \
                patch.dict(sys.modules, {"certifi": None}):
            with self.assertRaisesRegex(receipt_agent.TransportError, "no TLS CA roots"):
                REAL_MCP("https://cairn.example/mcp", "ab" * 32)


if __name__ == "__main__":
    unittest.main()
