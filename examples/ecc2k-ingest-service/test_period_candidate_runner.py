import os
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

import period_candidate_runner as runner


class FakeCursor:
    def __init__(self, read_only="on", writable=False, readable=True,
                 role_flags=(False, False, False)):
        self.read_only = read_only
        self.writable = writable
        self.readable = readable
        self.role_flags = role_flags
        self.result = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def execute(self, query, params=None):
        if query == "SHOW transaction_read_only":
            self.result = (self.read_only,)
        elif "FROM pg_catalog.pg_roles" in query:
            self.result = self.role_flags
        elif "has_table_privilege" in query:
            if params[1] == "SELECT":
                self.result = (self.readable,)
            elif self.writable:
                self.result = (True,)
            else:
                self.result = (False,)
        else:
            raise AssertionError(f"unexpected read-only preflight query: {query}")

    def fetchone(self):
        return self.result


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        return False

    def cursor(self):
        return self._cursor


class PeriodCandidateRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "dp_ingest.py"
        self.source.write_text(
            "import os\n"
            "def databaseUrl():\n"
            "    assert os.environ['RHO_DB_SECRET'] == 'auditor-ro-secret'\n"
            "    assert os.environ['RHO_DB_HOST'] == 'db.example.invalid'\n"
            "    assert os.environ['AWS_DEFAULT_REGION'] == 'eu-central-1'\n"
            "    assert os.environ['AWS_REGION'] == 'eu-central-1'\n"
            "    return 'postgresql://auditor@db.example.invalid/rho'\n"
        )

    def args(self, *extra):
        return [
            "--ingest-source", str(self.source),
            "--db-secret", "auditor-ro-secret",
            "--aws-region", "eu-central-1",
            "--db-instance", "test-rho",
            "--bucket", "private-evidence",
            "--replica-id", "replica-a",
            "--watch-from", "8",
            "--out-dir", str(Path(self.temp.name) / "candidates"),
            *extra,
        ]

    def fake_modules(self, cursor, observed):
        boto3 = types.ModuleType("boto3")

        class FakeRds:
            def describe_db_instances(self, **kwargs):
                observed["describe"] = kwargs
                return {"DBInstances": [{"Endpoint": {"Address": "db.example.invalid"}}]}

        def client(service, **kwargs):
            observed["database_url_during_aws_client"] = os.environ.get("DATABASE_URL")
            observed.setdefault("clients", []).append((service, kwargs))
            if service != "rds":
                raise AssertionError(f"unexpected AWS client: {service}")
            return FakeRds()

        boto3.client = client
        psycopg = types.ModuleType("psycopg")

        def connect(database_url, **kwargs):
            observed.setdefault("connections", []).append(
                (database_url, kwargs, os.environ.get("PGOPTIONS"), os.environ.get("DATABASE_URL"))
            )
            return FakeConnection(cursor)

        psycopg.connect = connect
        return {"boto3": boto3, "psycopg": psycopg}

    def test_requires_explicit_secret_and_rejects_inherited_database_url(self):
        with patch.dict(sys.modules, {"boto3": None, "psycopg": None}):
            with redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                runner.main(["--ingest-source", str(self.source), "--bucket", "b"])
            with patch.dict(os.environ, {"DATABASE_URL": "postgresql://writer@db/rho"}), \
                    redirect_stderr(StringIO()), self.assertRaises(SystemExit):
                runner.main(self.args())

    def test_selects_ro_secret_checks_connection_and_cleans_environment(self):
        original = {
            "AWS_DEFAULT_REGION": "old-default",
            "AWS_REGION": "old-region",
            "PGOPTIONS": "unsafe-option",
            "RHO_DB_HOST": "old-db",
            "RHO_DB_SECRET": "writer-secret",
        }
        observed = {}
        cursor = FakeCursor()
        modules = self.fake_modules(cursor, observed)
        with patch.dict(os.environ, original, clear=True), patch.dict(sys.modules, modules):
            original_sys_path = sys.path[:]
            def candidate_run(args, database_url=None):
                self.assertEqual(database_url, "postgresql://auditor@db.example.invalid/rho")
                self.assertNotIn("DATABASE_URL", os.environ)
                self.assertEqual(
                    os.environ["PGOPTIONS"],
                    "-c default_transaction_read_only=on -c statement_timeout=60000",
                )
                # Every candidate DB connection receives the URL in memory;
                # AWS credential subprocesses do not inherit it.
                sys.modules["psycopg"].connect(
                    "postgresql://auditor@db.example.invalid/rho"
                )
                return 17

            with patch.object(runner.period_candidate, "main", side_effect=candidate_run) as candidate:
                self.assertEqual(runner.main(self.args()), 17)
                candidate.assert_called_once_with([
                    "--bucket", "private-evidence", "--replica-id", "replica-a",
                    "--watch-from", "8", "--out-dir", str(Path(self.temp.name) / "candidates"),
                ], database_url="postgresql://auditor@db.example.invalid/rho")
                self.assertEqual(observed["describe"], {"DBInstanceIdentifier": "test-rho"})
                self.assertEqual(observed["clients"], [("rds", {"region_name": "eu-central-1"})])
                self.assertIsNone(observed["database_url_during_aws_client"])
                self.assertEqual(len(observed["connections"]), 2)
                self.assertEqual(
                    observed["connections"][0],
                    (
                        "postgresql://auditor@db.example.invalid/rho",
                        {"connect_timeout": 10},
                        "-c default_transaction_read_only=on -c statement_timeout=60000",
                        None,
                    ),
                )
                self.assertEqual(
                    observed["connections"][1],
                    (
                        "postgresql://auditor@db.example.invalid/rho",
                        {},
                        "-c default_transaction_read_only=on -c statement_timeout=60000",
                        None,
                    ),
                )
            self.assertEqual(
                {key: os.environ[key] for key in original},
                original,
            )
            self.assertNotIn("DATABASE_URL", os.environ)
            self.assertEqual(sys.path, original_sys_path)

    def test_refuses_non_readonly_session_or_privileged_role_before_candidate(self):
        for cursor in (
            FakeCursor(read_only="off"),
            FakeCursor(role_flags=(True, False, False)),
            FakeCursor(writable=True),
            FakeCursor(readable=False),
        ):
            observed = {}
            modules = self.fake_modules(cursor, observed)
            with self.subTest(cursor=cursor), patch.dict(os.environ, {}, clear=True), patch.dict(sys.modules, modules):
                with patch.object(runner.period_candidate, "main") as candidate:
                    with self.assertRaises(RuntimeError):
                        runner.main(self.args())
                    candidate.assert_not_called()
                self.assertNotIn("DATABASE_URL", os.environ)
                self.assertNotIn("RHO_DB_SECRET", os.environ)
                self.assertNotIn("PGOPTIONS", os.environ)


if __name__ == "__main__":
    unittest.main()
