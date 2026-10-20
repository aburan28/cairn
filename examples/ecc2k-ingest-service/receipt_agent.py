#!/usr/bin/env python3
"""Submit independently signed ingester periods through Cairn MCP.

The durable journal stops on an uncertain commit or reveal response. An
operator must inspect the Cairn log before clearing that state; retrying a
write whose response was lost could create a second commitment.
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit


class TransportError(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        raise TransportError("MCP redirect refused")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def private_token(path):
    path = Path(path)
    if path.is_symlink() or not path.is_file() or stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ValueError("bearer token file must be private and must not be a symlink")
    token = path.read_text(encoding="ascii").strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("bearer token must be 64 lowercase hexadecimal characters")
    return token


def check_endpoint(url, allow_loopback_http=False):
    parsed = urlsplit(url)
    if (parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path != "/mcp" or not parsed.hostname):
        raise ValueError("endpoint must be a credential-free URL ending in /mcp")
    if parsed.scheme == "https":
        return url
    if (allow_loopback_http and parsed.scheme == "http"
            and parsed.hostname in ("127.0.0.1", "localhost", "::1")):
        return url
    raise ValueError("Cairn MCP needs HTTPS; loopback HTTP is for local tests")


class MCP:
    def __init__(self, url, token):
        self.url, self.token, self.session = url, token, None
        # An agent bearer belongs to this endpoint. Environment proxies and
        # redirects could send it somewhere else without the agent noticing.
        self.opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), NoRedirect())

    def request(self, method, body=None):
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/json, text/event-stream"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        request = urllib.request.Request(
            self.url, data=canonical(body) if body is not None else None,
            headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=180) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
                if len(raw) > 16 * 1024 * 1024:
                    raise TransportError("MCP response exceeds 16 MiB")
                if method == "POST":
                    if self.session is None:
                        self.session = response.headers.get("Mcp-Session-Id")
                    return json.loads(raw)
        except (OSError, ValueError, urllib.error.HTTPError) as error:
            raise TransportError(f"MCP {method} failed: {error}") from error
        return None

    def initialize(self):
        answer = self.request("POST", {"jsonrpc": "2.0", "id": 1,
                                       "method": "initialize",
                                       "params": {"protocolVersion": "2025-06-18"}})
        if not self.session or answer.get("result", {}).get("protocolVersion") != "2025-06-18":
            raise TransportError("Cairn MCP initialization failed")

    def tool(self, name, arguments):
        answer = self.request("POST", {"jsonrpc": "2.0", "id": 2,
                                       "method": "tools/call",
                                       "params": {"name": name, "arguments": arguments}})
        if answer.get("id") != 2 or "result" not in answer:
            raise TransportError("Cairn MCP tool response is incomplete")
        result = answer["result"]
        blocks = result.get("content")
        if not isinstance(blocks, list) or not blocks or not isinstance(blocks[0], dict):
            raise TransportError("Cairn MCP tool content is missing")
        text = blocks[0].get("text", "")
        if not isinstance(text, str):
            raise TransportError("Cairn MCP tool text is malformed")
        return result, text

    def close(self):
        if self.session:
            try:
                self.request("DELETE")
            except TransportError:
                pass


def atomic_json(path, value):
    data = canonical(value) + b"\n"
    temp = path.with_name(path.name + ".tmp-" + str(os.getpid()))
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temp.unlink(missing_ok=True)


def receipt_from(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{path}: receipt must be a regular file")
    artifact = json.loads(path.read_bytes())
    if type(artifact) is not dict or set(artifact) != {"body", "unit", "signature"}:
        raise ValueError(f"{path}: invalid signed receipt shape")
    body = artifact["body"]
    if (type(body) is not dict or type(body.get("replica_id")) is not str
            or type(body.get("period")) is not int or body["period"] < 0
            or artifact["unit"] != f"{body['replica_id']}:{body['period']}"):
        raise ValueError(f"{path}: invalid replica-period unit")
    data = canonical(artifact)
    if len(data) > 900_000:
        raise ValueError(f"{path}: receipt exceeds Cairn's 900 kB service limit")
    return artifact, data, hashlib.sha256(data).hexdigest()


class ReceiptAgent:
    def __init__(self, endpoint, token_file, objective_id, inbox, state_dir,
                 expected_unit_price=None, allow_loopback_http=False):
        self.endpoint = check_endpoint(endpoint, allow_loopback_http)
        self.token_file = Path(token_file)
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", objective_id):
            raise ValueError("objective_id must be a Cairn SHA-256 id")
        self.objective_id = objective_id
        self.inbox, self.state_dir = Path(inbox), Path(state_dir)
        if not self.inbox.is_dir() or self.inbox.is_symlink():
            raise ValueError("signed receipt inbox must be a directory")
        self.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.state_dir.is_symlink() or stat.S_IMODE(self.state_dir.stat().st_mode) & 0o077:
            raise ValueError("journal directory must be private")
        if expected_unit_price is not None and expected_unit_price < 1:
            raise ValueError("expected unit price must be positive")
        self.expected_unit_price = expected_unit_price

    def save(self, path, state):
        atomic_json(path, state)
        return state

    def advance(self, client, path, state, artifact, now):
        phase = state["phase"]
        args = {"objective_id": self.objective_id, "submitter": "ingest-service-agent",
                "artifact": artifact}
        if phase == "new":
            result, text = client.tool("score_candidate", args)
            if result.get("isError"):
                raise ValueError(f"score_candidate failed for {state['unit']}: {text[:200]}")
            first = text.splitlines()[0].split(":", 1)[0] if text else ""
            if first == "unavailable":
                return state
            if first == "reject":
                return self.save(path, state | {"phase": "rejected", "detail": text[:200]})
            if first != "accept":
                raise ValueError(f"unexpected score_candidate verdict for {state['unit']}")
            state = self.save(path, state | {"phase": "scored"})
            phase = "scored"
        if phase in ("scored", "committed"):
            if phase == "committed" and now < state.get("next_action_at", 0):
                return state
            inflight = "commit_inflight" if phase == "scored" else "reveal_inflight"
            state = self.save(path, state | {"phase": inflight})
            result, text = client.tool("submit_claim", args)
            meta = result.get("_meta", {})
            reason = meta.get("cairn/reason")
            if result.get("isError"):
                return self.save(path, state | {"phase": "manual_review",
                                                "detail": f"{reason}: {text[:200]}"})
            if reason in ("committed", "already_committed"):
                wait = meta.get("cairn/wait", {}).get("reveal_in_seconds")
                if type(wait) is not int or wait < 0:
                    raise ValueError("Cairn did not return the reveal wait")
                return self.save(path, state | {"phase": "committed",
                                                "next_action_at": now + wait + 1})
            if reason == "revealed" and meta.get("cairn/verdict") == "accept":
                claim_id = meta.get("cairn/claim_id")
                if not isinstance(claim_id, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", claim_id):
                    raise ValueError("Cairn reveal did not return a claim id")
                return self.save(path, state | {"phase": "revealed", "claim_id": claim_id})
            return self.save(path, state | {"phase": "manual_review",
                                            "detail": f"unexpected submission result: {reason}"})
        if phase == "revealed":
            result, text = client.tool("get_claim", {"claim_id": state["claim_id"]})
            if result.get("isError"):
                raise ValueError(f"get_claim failed for {state['unit']}: {text[:200]}")
            meta = result.get("_meta") or {}
            if type(meta) is not dict:
                raise ValueError(f"malformed Cairn metadata for {state['unit']}")
            payment = meta.get("cairn/payment")
            if payment is not None:
                if (type(payment) is not dict or set(payment) != {"state", "reward"}
                        or payment["state"] not in ("paid", "unpaid", "pending")):
                    raise ValueError(f"malformed Cairn payment state for {state['unit']}")
                if payment["state"] == "pending":
                    if payment["reward"] is not None:
                        raise ValueError("pending Cairn payment has a reward")
                    return state
                reward = payment["reward"]
                if (type(reward) is not int or reward < 0
                        or (payment["state"] == "paid") != (reward > 0)):
                    raise ValueError(f"inconsistent Cairn payment for {state['unit']}")
                final = ("unpaid" if reward == 0 else
                         "payment_mismatch" if self.expected_unit_price is not None
                         and reward != self.expected_unit_price else "paid")
                return self.save(path, state | {"phase": final, "reward": reward})
            # Older Cairn nodes only expose paid settlements in prose. Their
            # pending line also covers final zero payouts, so it cannot close
            # an unpaid journal entry without the batch metadata above.
            header = text.split("\n--- BEGIN UNTRUSTED ARTIFACT ---", 1)[0]
            match = re.search(r"^settled: yes, reward ([0-9]+)$", header, re.MULTILINE)
            if match:
                reward = int(match.group(1))
                final = ("unpaid" if reward == 0 else
                         "payment_mismatch" if self.expected_unit_price is not None
                         and reward != self.expected_unit_price else "paid")
                return self.save(path, state | {"phase": final, "reward": reward})
        return state

    def run_once(self):
        lock_path = self.state_dir / "agent.lock"
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        with os.fdopen(fd, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            receipts = {}
            units = {}
            for state_path in sorted(self.state_dir.glob("*.state.json")):
                if state_path.is_symlink():
                    raise ValueError("journal state must not be a symlink")
                state = json.loads(state_path.read_text())
                if type(state) is not dict:
                    raise ValueError("journal state must be an object")
                digest = state.get("digest")
                if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest)
                        or state_path.name != digest + ".state.json"
                        or state.get("schema") != "cairn-receipt-agent-v1"
                        or state.get("objective_id") != self.objective_id
                        or state.get("phase") not in {
                            "new", "scored", "commit_inflight", "committed",
                            "reveal_inflight", "revealed", "paid", "unpaid",
                            "rejected", "manual_review", "payment_mismatch"}):
                    raise ValueError("journal does not match objective or receipt")
                receipt_copy = self.state_dir / (digest + ".artifact.json")
                artifact, data, observed = receipt_from(receipt_copy)
                if observed != digest or state.get("unit") != artifact["unit"]:
                    raise ValueError("journal artifact is corrupt or mismatched")
                if artifact["unit"] in units and units[artifact["unit"]] != digest:
                    raise ValueError(f"conflicting journal entries for {artifact['unit']}")
                units[artifact["unit"]] = digest
                receipts[digest] = (artifact, state_path, state)
            for source in sorted(self.inbox.glob("*.receipt.json")):
                artifact, data, digest = receipt_from(source)
                prior = units.get(artifact["unit"])
                if prior is not None and prior != digest:
                    raise ValueError(f"conflicting signed receipts for {artifact['unit']}")
                units[artifact["unit"]] = digest
                if digest in receipts:
                    continue
                receipt_copy = self.state_dir / (digest + ".artifact.json")
                if not receipt_copy.exists():
                    fd = os.open(receipt_copy, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                    with os.fdopen(fd, "wb") as output:
                        output.write(data)
                        output.flush()
                        os.fsync(output.fileno())
                elif receipt_copy.read_bytes() != data:
                    raise ValueError("journal artifact digest collision or corruption")
                state_path = self.state_dir / (digest + ".state.json")
                state = self.save(state_path, {"schema": "cairn-receipt-agent-v1",
                                               "objective_id": self.objective_id,
                                               "digest": digest, "unit": artifact["unit"],
                                               "phase": "new"})
                receipts[digest] = (artifact, state_path, state)
            if not receipts:
                return
            client = MCP(self.endpoint, private_token(self.token_file))
            try:
                client.initialize()
                for artifact, state_path, state in receipts.values():
                    if state["phase"] in ("paid", "unpaid", "rejected"):
                        continue
                    if state["phase"] in ("commit_inflight", "reveal_inflight",
                                           "manual_review", "payment_mismatch"):
                        raise ValueError(f"{state['unit']}: {state['phase']} needs operator review")
                    self.advance(client, state_path, state, artifact, time.time())
            finally:
                client.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--objective-id", required=True)
    parser.add_argument("--inbox", required=True)
    parser.add_argument("--state-dir", required=True)
    parser.add_argument("--expected-unit-price", type=int)
    parser.add_argument("--watch", action="store_true")
    parser.add_argument("--interval", type=int, default=30)
    parser.add_argument("--allow-loopback-http", action="store_true",
                        help="for a local test only")
    args = parser.parse_args(argv)
    if args.interval < 1:
        parser.error("--interval must be positive")
    agent = ReceiptAgent(args.endpoint, args.token_file, args.objective_id,
                         args.inbox, args.state_dir, args.expected_unit_price,
                         args.allow_loopback_http)
    while True:
        try:
            agent.run_once()
        except ValueError as error:
            print(f"receipt agent: {error}", file=sys.stderr)
            return 1
        except (OSError, TransportError) as error:
            print(f"receipt agent: {error}", file=sys.stderr)
            if not args.watch:
                return 1
        if not args.watch:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    raise SystemExit(main())
