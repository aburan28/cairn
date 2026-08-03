"""Verifier behaviour, especially the cases where saying the wrong thing is an attack."""
import hashlib
import json
import os

import pytest

from proofwork import verifiers
from proofwork.verifiers import Status

CHECKER = '''
def check(artifact):
    return artifact.get("n") == 42
'''

EVALUATOR = '''
def score(artifact):
    return len(artifact.get("items", []))
'''

FLOAT_EVALUATOR = '''
def score(artifact):
    return 3.5
'''


def write_pinned(tmp_path, name, source):
    path = tmp_path / name
    path.write_text(source)
    return name, hashlib.sha256(source.encode()).hexdigest()


@pytest.fixture(autouse=True)
def _root(tmp_path):
    verifiers.set_root(str(tmp_path))
    yield
    verifiers.set_root(".")


# -- certificate -----------------------------------------------------------


def test_certificate_accepts_a_real_witness(tmp_path):
    name, sha = write_pinned(tmp_path, "c.py", CHECKER)
    spec = {"kind": "certificate", "checker": name, "checker_sha256": sha, "entrypoint": "check"}
    assert verifiers.run(spec, {"n": 42}).status is Status.ACCEPT


def test_certificate_rejects_a_bad_witness(tmp_path):
    name, sha = write_pinned(tmp_path, "c.py", CHECKER)
    spec = {"kind": "certificate", "checker": name, "checker_sha256": sha, "entrypoint": "check"}
    assert verifiers.run(spec, {"n": 41}).status is Status.REJECT


def test_edited_checker_invalidates_the_spec_rather_than_silently_rescoring(tmp_path):
    name, sha = write_pinned(tmp_path, "c.py", CHECKER)
    (tmp_path / name).write_text(CHECKER.replace("42", "41"))
    spec = {"kind": "certificate", "checker": name, "checker_sha256": sha, "entrypoint": "check"}
    verdict = verifiers.run(spec, {"n": 41})
    assert verdict.status is Status.INVALID_SPEC
    assert not verdict.status.settles


def test_missing_checker_is_unavailable_not_a_rejection(tmp_path):
    spec = {
        "kind": "certificate",
        "checker": "nope.py",
        "checker_sha256": "0" * 64,
        "entrypoint": "check",
    }
    assert verifiers.run(spec, {"n": 42}).status is Status.UNAVAILABLE


def test_pinned_path_cannot_escape_the_root(tmp_path):
    spec = {
        "kind": "certificate",
        "checker": "../outside.py",
        "checker_sha256": "0" * 64,
        "entrypoint": "check",
    }
    assert verifiers.run(spec, {}).status in (Status.INVALID_SPEC, Status.UNAVAILABLE)


def test_crashing_checker_is_unavailable(tmp_path):
    name, sha = write_pinned(tmp_path, "boom.py", "def check(a):\n    raise RuntimeError('x')\n")
    spec = {"kind": "certificate", "checker": name, "checker_sha256": sha, "entrypoint": "check"}
    assert verifiers.run(spec, {}).status is Status.UNAVAILABLE


# -- evaluator -------------------------------------------------------------


def test_evaluator_threshold(tmp_path):
    name, sha = write_pinned(tmp_path, "e.py", EVALUATOR)
    spec = {
        "kind": "evaluator",
        "evaluator": name,
        "evaluator_sha256": sha,
        "entrypoint": "score",
        "threshold": 3,
        "direction": "maximize",
    }
    assert verifiers.run(spec, {"items": [1, 2, 3]}).status is Status.ACCEPT
    assert verifiers.run(spec, {"items": [1, 2]}).status is Status.REJECT


def test_evaluator_refuses_float_scores(tmp_path):
    # A float score can compare differently on different hardware, so two honest
    # nodes could disagree about whether the threshold was met.
    name, sha = write_pinned(tmp_path, "f.py", FLOAT_EVALUATOR)
    spec = {
        "kind": "evaluator",
        "evaluator": name,
        "evaluator_sha256": sha,
        "entrypoint": "score",
        "threshold": 3,
    }
    verdict = verifiers.run(spec, {})
    assert verdict.status is Status.INVALID_SPEC
    assert "int" in verdict.detail


def test_evaluator_requires_integer_threshold(tmp_path):
    name, sha = write_pinned(tmp_path, "e.py", EVALUATOR)
    spec = {
        "kind": "evaluator",
        "evaluator": name,
        "evaluator_sha256": sha,
        "entrypoint": "score",
        "threshold": 3.5,
    }
    assert verifiers.run(spec, {}).status is Status.INVALID_SPEC


# -- lean ------------------------------------------------------------------


def test_lean_rejects_sorry_without_needing_a_toolchain():
    # Checked before Lean runs: `sorry` compiles and proves nothing.
    spec = {"kind": "lean", "statement": "theorem t : True"}
    verdict = verifiers.run(spec, {"proof": ":= by sorry"})
    assert verdict.status is Status.REJECT
    assert "sorry" in verdict.detail


@pytest.mark.parametrize(
    "proof",
    [":= by admit", ":= by native_decide", "axiom cheat : True"],
)
def test_lean_rejects_the_other_escape_hatches(proof):
    spec = {"kind": "lean", "statement": "theorem t : True"}
    assert verifiers.run(spec, {"proof": proof}).status is Status.REJECT


def test_lean_allows_native_decide_when_the_objective_opts_in(monkeypatch):
    spec = {"kind": "lean", "statement": "theorem t : True", "allow_native_decide": True}
    verdict = verifiers.run(spec, {"proof": ":= by native_decide"})
    # Passes the pre-screen; the verdict then depends on whether Lean is present.
    assert verdict.status is not Status.REJECT


def test_missing_lean_toolchain_is_unavailable_not_a_rejection(monkeypatch):
    # The failure mode this prevents: take verifiers offline and every honest
    # submission "fails". An absent toolchain says nothing about the proof.
    monkeypatch.setattr("shutil.which", lambda _: None)
    spec = {"kind": "lean", "statement": "theorem t : True"}
    verdict = verifiers.run(spec, {"proof": ":= by trivial"})
    assert verdict.status is Status.UNAVAILABLE
    assert not verdict.status.settles


def test_lean_needs_a_statement_from_the_objective():
    # The statement comes from the objective, never the submitter -- otherwise a
    # submitter proves an easier theorem and collects.
    assert verifiers.run({"kind": "lean"}, {"proof": ":= by trivial"}).status is Status.INVALID_SPEC


# -- replay ----------------------------------------------------------------


def test_replay_reproduces_declared_fields(tmp_path):
    script = tmp_path / "run.py"
    script.write_text("import json; print(json.dumps({'count': 7}))")
    spec = {
        "kind": "replay",
        "command": ["python3", "run.py"],
        "reproducible_fields": ["count"],
    }
    assert verifiers.run(spec, {"results": {"count": 7}}).status is Status.ACCEPT
    assert verifiers.run(spec, {"results": {"count": 8}}).status is Status.REJECT


def test_replay_refuses_machine_dependent_fields(tmp_path):
    # A cost claim denominated in seconds is a claim about somebody's hardware
    # and cannot be settled by re-execution.
    for field in ("wall_clock_seconds", "peak_memory", "elapsed", "flops"):
        spec = {"kind": "replay", "command": ["true"], "reproducible_fields": [field]}
        verdict = verifiers.run(spec, {"results": {}})
        assert verdict.status is Status.INVALID_SPEC, field


def test_replay_failure_is_unavailable_not_a_rejection(tmp_path):
    spec = {
        "kind": "replay",
        "command": ["python3", "-c", "raise SystemExit(3)"],
        "reproducible_fields": ["count"],
    }
    assert verifiers.run(spec, {"results": {"count": 1}}).status is Status.UNAVAILABLE


@pytest.mark.parametrize("escape", ["/", "/etc", "..", "../..", "a/../../.."])
def test_replay_cwd_cannot_escape_the_objective_root(escape):
    # Regression, mirrored in the Rust suite. ``cwd`` is objective-authored;
    # unconfined it pointed the command at any host directory the record
    # named, with declared fields as the exfiltration channel.
    spec = {
        "kind": "replay",
        "command": ["true"],
        "reproducible_fields": ["n"],
        "cwd": escape,
    }
    verdict = verifiers.run(spec, {"results": {}})
    assert verdict.status is Status.INVALID_SPEC, escape
    assert "escapes" in verdict.detail


@pytest.mark.parametrize("escape", ["/", "/etc", "..", "../.."])
def test_lean_project_root_cannot_escape_the_objective_root(escape):
    # Regression, mirrored in the Rust suite, where ``project_root`` is bound
    # into the verifier jail *writable* -- "/" turned the jail into a
    # pass-through. Screened before the toolchain lookup, so this refusal is
    # testable without Lean installed.
    spec = {
        "kind": "lean",
        "statement": "theorem t : True",
        "project_root": escape,
    }
    verdict = verifiers.run(spec, {"proof": ":= trivial"})
    assert verdict.status is Status.INVALID_SPEC, escape
    assert "escapes" in verdict.detail


# -- dispatch --------------------------------------------------------------


def test_unknown_verifier_kind_is_unavailable():
    assert verifiers.run({"kind": "haruspicy"}, {}).status is Status.UNAVAILABLE


def test_spec_without_kind_is_invalid():
    assert verifiers.run({}, {}).status is Status.INVALID_SPEC


def test_only_accept_and_reject_settle():
    assert Status.ACCEPT.settles and Status.REJECT.settles
    assert not Status.UNAVAILABLE.settles
    assert not Status.INVALID_SPEC.settles
