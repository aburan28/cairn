#!/usr/bin/env python3
"""Run the unsigned period watcher using a dedicated auditor DB secret.

The AWS credential stays in this process. The selected database secret must
belong to a non-privileged role with SELECT access only to the ingester's
progress and poll tables. Session read-only mode is additional protection, not
a substitute for those database grants. This process loads no auditor key and
does not sign or submit receipts.
"""

import argparse
import importlib.util
import os
import sys
from pathlib import Path

import period_candidate


_OVERRIDDEN_ENV = (
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
    "PGOPTIONS",
    "RHO_DB_HOST",
    "RHO_DB_SECRET",
)
_READ_ONLY_OPTIONS = (
    "-c default_transaction_read_only=on -c statement_timeout=60000"
)
_TABLES = ("dp_ingest_progress", "dp_ingest_polls")
_WRITE_PRIVILEGES = ("INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER")


def _restore_environment(saved):
    for name, value in saved.items():
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value


def _check_read_only_connection(connection):
    with connection.cursor() as cursor:
        cursor.execute("SHOW transaction_read_only")
        row = cursor.fetchone()
        if row is None or row[0] != "on":
            raise RuntimeError("auditor database session is not read-only")

        cursor.execute(
            "SELECT rolsuper, rolcreatedb, rolcreaterole "
            "FROM pg_catalog.pg_roles WHERE rolname = current_user"
        )
        role = cursor.fetchone()
        if role is None or any(role):
            raise RuntimeError("auditor database role must be non-privileged")

        for table in _TABLES:
            cursor.execute(
                "SELECT has_table_privilege(current_user, %s, %s)",
                (f"public.{table}", "SELECT"),
            )
            readable = cursor.fetchone()
            if readable is None or not readable[0]:
                raise RuntimeError(
                    "auditor database role lacks SELECT access to an ingester table"
                )
            for privilege_name in _WRITE_PRIVILEGES:
                cursor.execute(
                    "SELECT has_table_privilege(current_user, %s, %s)",
                    (f"public.{table}", privilege_name),
                )
                privilege = cursor.fetchone()
                if privilege is None or privilege[0]:
                    raise RuntimeError(
                        "auditor database role has write access to an ingester table"
                    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ingest-source", type=Path, required=True)
    parser.add_argument(
        "--db-secret",
        required=True,
        help="Secrets Manager id for a dedicated SELECT-only auditor database role",
    )
    parser.add_argument("--db-instance", default="rho-dp")
    parser.add_argument("--aws-region", default="us-west-2")
    options, candidate_args = parser.parse_known_args(argv)
    if not options.db_secret.strip():
        parser.error("--db-secret must select the dedicated auditor database secret")
    if os.environ.get("DATABASE_URL"):
        parser.error(
            "DATABASE_URL is set; unset it so this runner uses only --db-secret"
        )
    source = options.ingest_source.resolve(strict=True)
    if source.name != "dp_ingest.py" or not source.is_file():
        parser.error("--ingest-source must name the installed dp_ingest.py")

    saved = {name: os.environ.get(name) for name in _OVERRIDDEN_ENV}
    old_sys_path = sys.path[:]
    old_umask = os.umask(0o077)
    try:
        os.environ["AWS_DEFAULT_REGION"] = options.aws_region
        os.environ["AWS_REGION"] = options.aws_region
        os.environ["RHO_DB_SECRET"] = options.db_secret
        os.environ["PGOPTIONS"] = _READ_ONLY_OPTIONS

        import boto3
        import psycopg

        host = boto3.client("rds", region_name=options.aws_region).describe_db_instances(
            DBInstanceIdentifier=options.db_instance
        )["DBInstances"][0]["Endpoint"]["Address"]
        os.environ["RHO_DB_HOST"] = host
        sys.path.insert(0, str(source.parent))
        spec = importlib.util.spec_from_file_location("auditor_installed_dp_ingest", source)
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load the installed dp_ingest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        database_url = module.databaseUrl()
        if not database_url:
            raise RuntimeError("installed dp_ingest.py did not resolve a database URL")
        with psycopg.connect(database_url, connect_timeout=10) as connection:
            _check_read_only_connection(connection)
        return period_candidate.main(candidate_args, database_url=database_url)
    finally:
        _restore_environment(saved)
        sys.path[:] = old_sys_path
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
