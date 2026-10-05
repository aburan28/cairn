#!/usr/bin/env python3
"""Work a Koblitz orbit search as one worker of many, against a cairn node.

    python3 examples/certicom-ecdlp/tools/orbit_worker.py \\
        --node http://127.0.0.1:8080 \\
        --job examples/certicom-ecdlp/jobs/ecc2k-23.json \\
        --objective sha256:... --worker alice

The loop a distributed worker runs, written out once so that every client --
this one, the GPU client in aburan28/crypto, an agent over MCP -- does the
same four things in the same order and shows up the same way on the node's
dashboard (`/ui/task?id=...`):

1. **Ask for a slice.** `GET /work_assignment` hands this worker its unit
   range for the epoch. It is a pure function of public inputs, so nobody
   reserved anything and two workers that overlap merely duplicate a little
   compute; it rotates every epoch, so this loop asks again when the epoch
   turns.
2. **Walk it.** Each unit is a family of trails, `seed = (unit << trail_bits)
   | trail`; each trail runs to a distinguished orbit or to the step cap.
   The walk is `orbit_dp.py`'s, byte for byte -- this file adds no arithmetic.
3. **Say so.** A heartbeat to `POST /progress` every `--heartbeat` seconds:
   the slice, the unit, steps and trails this session, orbits waiting for the
   next batch, and the rate. That is how an operator sees the worker is alive
   and what it is on. It is not a record, it is not verified, and it pays
   nothing; the node labels it as reported and so should you.
4. **Submit.** When `--batch` orbits are waiting, commit them in this epoch
   over `POST /submit?kind=commitment` and reveal them in the next over
   `POST /submit?kind=claim`. Those are the records; what they settle is what
   the dashboard shows under *settled*, and what the worker is paid.

# Why the submission waits for the clock

The node derives a record's epoch from its own `created_at`, and admits a
commitment only when the epoch it drains it in is the one the record names
(`Node::commit`). The node drains its queue every five seconds, so a record
posted in the last seconds of an epoch is drained in the next and refused.
This loop therefore posts nothing in the final `--margin` seconds of an epoch
and holds the record until the next one begins. A reveal must also land in an
epoch strictly after its commitment's, so a committed batch waits in
`pending_reveals` for the turn and the loop keeps walking meanwhile.

# What this is not

Fast. CPython walks ECC2K-23 in milliseconds and ECC2K-130 in hours per
trail; the client that actually runs the latter is the bitsliced GPU walker
in `aburan28/crypto` (`ecc2k130/`). This loop is the reference for what that
client posts and when, and the thing to run on the 21-bit twin to watch a
fleet appear on the dashboard in a minute: `scripts/progress-demo.sh` does
exactly that.

Nothing here reads the log. Whether a batch was paid is the node's business
and is on `GET /progress/{id}` under `derived`; a worker that wants to know
asks there rather than re-deriving settlement for itself.
"""
import argparse
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import orbit_dp as O  # noqa: E402

CLIENT = "orbit_worker.py/1"


# -- the node ------------------------------------------------------------------


class Member:
    """A fleet membership: the member file `cairn fleet join` wrote.

    This file reads the file's public fields and never its secret. Each POST
    is signed by `cairn fleet sign`, one subprocess per request, which builds
    the request string itself and signs nothing else; Python big-integer
    arithmetic is not constant-time, and a rented box has neighbours
    (`docs/design/fleet-enrollment.md` §11).
    """

    def __init__(self, path, cairn="cairn"):
        self.path = path
        self.cairn = cairn
        with open(path, encoding="utf-8") as handle:
            text = json.load(handle)
        self.node = text["node"]
        self.leader = text["leader"]
        self.name = text["name"]

    def authorize(self, method, target, data):
        result = subprocess.run(
            [self.cairn, "fleet", "sign", "--member", self.path, "--method", method, "--target", target],
            input=data or b"",
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(f"cairn fleet sign: {result.stderr.decode(errors='replace').strip()}")
        return result.stdout.decode().strip()


class Node:
    """The four HTTP calls, and nothing else about the node."""

    def __init__(self, base, timeout=30, member=None):
        self.base = base.rstrip("/")
        self.timeout = timeout
        self.member = member
        # A signature covers the request-target as sent, so a member's
        # requests go straight to the node: a proxy that rewrites the target
        # into an absolute URI would break every one of them.
        handlers = [urllib.request.ProxyHandler({})] if member else []
        self.opener = urllib.request.build_opener(*handlers)

    def _call(self, method, path, body=None):
        data = None
        headers = {"accept": "application/json"}
        if body is not None:
            data = json.dumps(body, separators=(",", ":"), ensure_ascii=False).encode()
            headers["content-type"] = "application/json"
        if self.member is not None and method == "POST":
            target = (urllib.parse.urlsplit(self.base).path or "") + path
            headers["authorization"] = self.member.authorize(method, target, data)
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                text = response.read().decode()
                return response.status, (json.loads(text) if text else None)
        except urllib.error.HTTPError as error:
            text = error.read().decode(errors="replace")
            try:
                return error.code, json.loads(text)
            except ValueError:
                return error.code, {"error": text.strip()}

    def assignment(self, objective_id, worker, partitions):
        status, body = self._call(
            "GET",
            f"/work_assignment?objective_id={objective_id}&node_id={urllib.request.quote(worker)}"
            f"&partitions={partitions}",
        )
        if status != 200:
            raise RuntimeError(f"work_assignment answered {status}: {body}")
        return body

    def heartbeat(self, body):
        return self._call("POST", "/progress", body)

    def submit(self, kind, record):
        return self._call("POST", f"/submit?kind={kind}", record)

    def progress(self, objective_id):
        return self._call("GET", f"/progress/{objective_id}")


def utc(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(seconds))


def commitment_hash(objective_id, submitter, artifact, nonce):
    """`cairn::records::commitment_hash`, which `conformance/vectors.json` pins."""
    inner = O._digest({"objective_id": objective_id, "artifact": artifact})
    return "sha256:" + hashlib.sha256(f"{inner}|{submitter}|{nonce}".encode()).hexdigest()


# -- the worker ----------------------------------------------------------------


class Worker:
    def __init__(self, args, job, node):
        self.args = args
        self.job = job
        self.node = node
        self.objective_id = args.objective
        self.name = args.worker
        # Whom the records name. A fleet worker names the leader, which signs
        # them on the way in; a lone worker names itself.
        self.submitter = args.submitter or args.worker
        self.started = time.time()
        self.steps = 0
        self.trails = 0
        self.capped = 0
        self.pending = []  # elements waiting for a batch
        self.pending_reveals = []  # (commit_epoch, artifact, nonce)
        self.submitted = 0  # units revealed, by our count
        self.revealed_batches = 0
        self.epoch_seconds = None
        self.assignment = None
        self.unit = None
        self.last_heartbeat = 0.0
        self.last_heartbeat_steps = 0
        self.rate = None
        # Every orbit this session has walked, by canonical x, with the seed
        # that reached it. A second trail reaching an orbit already here is a
        # collision -- the event the whole search is for -- and is reported
        # rather than resubmitted, because a batch that repeats an orbit is
        # refused whole and a paid orbit pays nobody twice.
        self.seen = {}
        self.collisions = []
        self.batch = args.batch or job.max_batch
        if self.batch > job.max_batch:
            raise SystemExit(f"--batch {self.batch} exceeds the job's max_batch {job.max_batch}")

    # ---- time -------------------------------------------------------------

    def epoch(self, at=None):
        return int(at if at is not None else time.time()) // self.epoch_seconds

    def seconds_left(self):
        now = time.time()
        return self.epoch_seconds - (now % self.epoch_seconds)

    def margin(self):
        # The drain tick is five seconds; a record posted later than this
        # before the boundary is drained on the wrong side of it.
        return min(self.args.margin, max(2, self.epoch_seconds // 3))

    def safe_to_post(self):
        return self.seconds_left() > self.margin()

    # ---- the four calls -------------------------------------------------

    def take_assignment(self):
        body = self.node.assignment(self.objective_id, self.name, self.args.partitions)
        if not body.get("units"):
            raise SystemExit("this objective is not divided into units; nothing for a worker to take")
        self.epoch_seconds = int(body["epoch_seconds"])
        self.assignment = body
        first, end = int(body["units"]["first"]), int(body["units"]["end"])
        say(f"epoch {body['epoch']}: units [{first}, {end}) of {body['units']['of']}, "
            f"partition {body['partition']} of {body['partitions']}, "
            f"{int(body['epoch_ends_in_seconds'])}s left")
        return first, end, int(body["epoch"])

    def send_heartbeat(self, force=False):
        now = time.time()
        if not force and now - self.last_heartbeat < self.args.heartbeat:
            return
        if self.last_heartbeat:
            span = now - self.last_heartbeat
            if span > 0:
                self.rate = int((self.steps - self.last_heartbeat_steps) / span)
        units = self.assignment["units"] if self.assignment else None
        body = {
            "objective_id": self.objective_id,
            "worker": self.name,
            "epoch": self.epoch(),
            "units": {"first": int(units["first"]), "end": int(units["end"])} if units else None,
            "unit": self.unit,
            "steps": self.steps,
            "trails": self.trails,
            "capped": self.capped,
            "units_pending": len(self.pending),
            "units_submitted": self.submitted,
            "steps_per_second": self.rate,
            "trail_bits": self.job.trail_bits,
            "client": CLIENT,
        }
        if self.args.device:
            body["device"] = self.args.device
        body = {k: v for k, v in body.items() if v is not None}
        status, answer = self.node.heartbeat(body)
        self.last_heartbeat = now
        self.last_heartbeat_steps = self.steps
        if status != 202:
            say(f"heartbeat refused ({status}): {answer}")
        elif answer and answer.get("ignored"):
            say(f"heartbeat: node ignored {answer['ignored']}")

    def batches_underway(self):
        """Batches committed or revealed so far, which is what `--max-batches`
        bounds: a commitment is a promise to reveal, so it counts before the
        reveal lands."""
        return self.revealed_batches + len(self.pending_reveals)

    def target_reached(self):
        return bool(self.args.max_batches) and self.batches_underway() >= self.args.max_batches

    def batches_wanted(self):
        """How many batches it is worth holding orbits for right now: one
        more than the in-flight cap, or fewer when --max-batches is near."""
        wanted = self.args.inflight + 1
        if self.args.max_batches:
            wanted = min(wanted, max(1, self.args.max_batches - self.batches_underway()))
        return wanted

    def commit(self):
        """Commit the waiting batch, if it is full, the clock allows, and not
        too much is already awaiting reveal.

        The in-flight cap is what keeps a fast walker from flooding the node:
        on the 21-bit twin a trail takes milliseconds, so without it one
        worker commits hundreds of batches an epoch and every one of them is
        a record the node must drain, verify and settle. A batch that is not
        committed stays in `pending` and is committed when a reveal clears.
        """
        if len(self.pending) < self.batch or not self.safe_to_post():
            return
        if len(self.pending_reveals) >= self.args.inflight or self.target_reached():
            return
        elements, self.pending = self.pending[: self.batch], self.pending[self.batch:]
        artifact = {"dps": elements}
        nonce = secrets.token_hex(16)
        now = time.time()
        record = {
            "type": "commitment",
            "objective_id": self.objective_id,
            "submitter": self.submitter,
            "hash": commitment_hash(self.objective_id, self.submitter, artifact, nonce),
            "created_at": utc(now),
        }
        status, answer = self.node.submit("commitment", record)
        if status == 202:
            self.pending_reveals.append((self.epoch(now), artifact, nonce))
            say(f"committed {len(elements)} orbit(s) in epoch {self.epoch(now)} ({answer.get('queued', '?')})")
        elif status == 429:
            # The node's queue is full; the batch goes back to the front and
            # is tried again on the next tick.
            self.pending = elements + self.pending
            say("node queue is full; holding the batch")
        else:
            self.pending = elements + self.pending
            say(f"commitment refused ({status}): {answer}")

    def reveal(self):
        """Open every commitment whose epoch has passed, if the clock allows."""
        if not self.pending_reveals or not self.safe_to_post():
            return
        now = time.time()
        current = self.epoch(now)
        keep = []
        for commit_epoch, artifact, nonce in self.pending_reveals:
            if commit_epoch >= current:
                keep.append((commit_epoch, artifact, nonce))
                continue
            record = {
                "type": "claim",
                "objective_id": self.objective_id,
                "submitter": self.submitter,
                "artifact": artifact,
                "nonce": nonce,
                "created_at": utc(now),
                "cites": [],
            }
            status, answer = self.node.submit("claim", record)
            if status == 202:
                self.submitted += len(artifact["dps"])
                self.revealed_batches += 1
                say(f"revealed {len(artifact['dps'])} orbit(s) from epoch {commit_epoch} in epoch {current}")
            elif status == 429:
                keep.append((commit_epoch, artifact, nonce))
                say("node queue is full; holding the reveal")
            else:
                # A refused reveal is a batch nobody will pay; say so loudly
                # and drop it rather than retrying a record the node has
                # already declined.
                say(f"reveal refused ({status}): {answer}; dropping {len(artifact['dps'])} orbit(s)")
        self.pending_reveals = keep

    def tick(self):
        self.send_heartbeat()
        self.commit()
        self.reveal()

    # ---- the walk ---------------------------------------------------------

    def unit_order(self, first, end):
        """The slice's units, starting from a point this worker's name picks.

        Two workers that hash into the same partition -- which the assignment
        permits and the twin, with few partitions, does often -- would
        otherwise walk the same seeds in the same order and reach the same
        orbits, the second of which pays nothing. Starting each at its own
        offset keeps them apart until one has walked the whole slice, and
        costs nothing, since every unit of the slice is walked in any case.
        """
        span = end - first
        if span <= 0:
            return []
        offset = int.from_bytes(hashlib.sha256(self.name.encode()).digest()[:8], "big") % span
        return [first + (offset + i) % span for i in range(span)]

    def found(self, canonical_x, seed, counts):
        """Keep a walked orbit for the next batch, unless this worker has
        reached it before, in which case it is a collision and is reported."""
        x = O.to_hex(canonical_x)
        earlier = self.seen.get(x)
        if earlier is not None:
            self.collisions.append((x, earlier, O.to_hex(seed)))
            say(f"collision: orbit {x} reached from seeds {earlier} and {O.to_hex(seed)}; "
                f"`orbit_dp.py collide` recovers the logarithm from the two witnesses")
            return
        self.seen[x] = O.to_hex(seed)
        self.pending.append(self.job.element(canonical_x, seed, counts))

    def run(self):
        deadline = self.started + self.args.seconds if self.args.seconds else None
        while True:
            first, end, epoch = self.take_assignment()
            self.send_heartbeat(force=True)
            for unit in self.unit_order(first, end):
                self.unit = unit
                for trail in range(1 << self.job.trail_bits):
                    if self.epoch() != epoch:
                        break
                    # Backpressure: with a batch waiting for every slot the
                    # in-flight cap allows -- or for every batch still wanted
                    # under --max-batches -- walking more only piles up orbits
                    # nothing will commit. Keep heartbeating and revealing
                    # instead, and resume when a slot clears.
                    while (
                        len(self.pending) >= self.batch * self.batches_wanted()
                        or self.target_reached()
                    ) and self.epoch() == epoch:
                        self.tick()
                        if self.done(deadline):
                            return self.finish()
                        time.sleep(0.2)
                    if self.epoch() != epoch:
                        break
                    seed = self.job.seed_of(unit, trail)
                    walked = self.job.walk(seed)
                    if walked is None:
                        self.capped += 1
                        self.steps += self.job.step_cap
                    else:
                        canonical_x, counts, steps = walked
                        self.steps += steps
                        self.trails += 1
                        self.found(canonical_x, seed, counts)
                    self.tick()
                    if self.done(deadline):
                        return self.finish()
                    if self.args.trails_per_unit and trail + 1 >= self.args.trails_per_unit:
                        break
                if self.epoch() != epoch:
                    break
            # The slice is exhausted or the epoch turned: idle out the epoch
            # (still heartbeating and revealing) and ask again.
            while self.epoch() == epoch:
                self.tick()
                if self.done(deadline):
                    return self.finish()
                time.sleep(min(1.0, max(0.1, self.seconds_left() / 4)))

    def done(self, deadline):
        """Time to stop walking: the batch target is reached (committed
        batches included; `finish` reveals them) or the clock ran out."""
        if self.target_reached():
            return True
        return deadline is not None and time.time() >= deadline

    def finish(self):
        """Reveal what was committed, then stop. Walked-but-uncommitted orbits
        are reported and dropped: a commitment nobody opens is never paid, and
        a batch below `--batch` was never committed."""
        waited = 0
        while self.pending_reveals and waited < 3 * self.epoch_seconds:
            self.reveal()
            if not self.pending_reveals:
                break
            time.sleep(1)
            waited += 1
        self.send_heartbeat(force=True)
        say(f"done: {self.trails} trails, {self.steps} steps, {self.submitted} orbits revealed in "
            f"{self.revealed_batches} batch(es), {len(self.pending)} orbit(s) walked and not submitted, "
            f"{len(self.pending_reveals)} batch(es) committed and not revealed, "
            f"{len(self.collisions)} collision(s) seen")
        return 0 if not self.pending_reveals else 2


def say(text):
    print(f"{time.strftime('%H:%M:%S')} {text}", file=sys.stderr, flush=True)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--node", default=None,
                        help="the node's HTTP address, e.g. http://127.0.0.1:8080 (with --fleet, the member file's)")
    parser.add_argument("--job", required=True, help="the version 2 search job document")
    parser.add_argument("--objective", required=True, help="the piecework objective id (sha256:...)")
    parser.add_argument("--worker", default=None,
                        help="your pseudonym: the node_id your work slice is drawn from, and the submitter "
                             "on every record unless --submitter says otherwise. With --fleet, a suffix: "
                             "gpu0 reports as <member name>/gpu0")
    parser.add_argument("--submitter", default=None,
                        help="submit under this name instead of --worker. On a leader's trusted network this "
                             "is its `signs_as` id: the leader signs the record and is paid for it, while "
                             "--worker stays this worker's own so each walks its own slice")
    parser.add_argument("--fleet", default=None,
                        help="work as an enrolled fleet member, from any address: the member file "
                             "`cairn fleet join` wrote. Records name its leader, which signs and is paid; "
                             "every POST is signed through `cairn fleet sign`")
    parser.add_argument("--cairn", default=os.environ.get("CAIRN_BIN", "cairn"),
                        help="the cairn binary that signs for --fleet (default: $CAIRN_BIN, then `cairn`)")
    parser.add_argument("--partitions", type=int, default=8, help="how many ways the space is split (default 8)")
    parser.add_argument("--batch", type=int, default=0, help="orbits per claim (default: the job's max_batch)")
    parser.add_argument("--heartbeat", type=float, default=30.0, help="seconds between heartbeats (default 30)")
    parser.add_argument("--margin", type=int, default=8,
                        help="post nothing in the last N seconds of an epoch (default 8; the drain tick is 5)")
    parser.add_argument("--trails-per-unit", type=int, default=0,
                        help="move to the next unit after N trails (default: exhaust the unit)")
    parser.add_argument("--inflight", type=int, default=2,
                        help="batches committed and awaiting reveal at once (default 2); the walker idles past it")
    parser.add_argument("--max-batches", type=int, default=0, help="stop after N batches are committed and revealed")
    parser.add_argument("--seconds", type=float, default=0, help="stop after N seconds")
    parser.add_argument("--device", default=None, help="what this worker runs on, for the roster")
    args = parser.parse_args(argv)

    member = None
    if args.fleet:
        if args.submitter:
            raise SystemExit("--fleet names the submitter already (the member file's leader); drop --submitter")
        member = Member(args.fleet, args.cairn)
        suffix = args.worker
        if suffix and ("/" in suffix or "|" in suffix or " " in suffix):
            raise SystemExit("with --fleet, --worker is a suffix such as gpu0: no `/`, `|` or spaces")
        # The leader key comes from the file, never from the node (G3).
        args.worker = f"{member.name}/{suffix}" if suffix else member.name
        args.submitter = member.leader
        args.node = args.node or member.node
    if not args.node:
        raise SystemExit("--node is required (or --fleet, whose member file names its leader)")
    if not args.worker:
        raise SystemExit("--worker is required")
    if "|" in args.worker or "|" in (args.submitter or ""):
        raise SystemExit("a worker or submitter name may not contain `|`: the commitment hash uses it as a separator")
    job = O.Job(O.load_job(args.job))
    say(f"{args.worker} on {job.job['name']} (job {job.id[:16]}…), batches of {args.batch or job.max_batch}, "
        f"node {args.node}" + (f", a fleet member of {member.leader[:12]}…" if member else ""))
    return Worker(args, job, Node(args.node, member=member)).run()


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(130)
