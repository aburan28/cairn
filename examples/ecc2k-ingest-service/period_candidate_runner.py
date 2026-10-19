#!/usr/bin/env python3
"""Run the unsigned period watcher with the ingester's existing AWS access.

The database credential stays in this process. Every database connection is
forced read-only, and no auditor signing key is loaded here.
"""

import argparse
import importlib.util
import os
import sys
from pathlib import Path

import boto3
import psycopg

import period_candidate


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, add_help=False)
    parser.add_argument("--ingest-source", type=Path, required=True)
    parser.add_argument("--db-instance", default="rho-dp")
    parser.add_argument("--aws-region", default="us-west-2")
    options, candidate_args = parser.parse_known_args(argv)
    source = options.ingest_source.resolve(strict=True)
    if source.name != "dp_ingest.py" or not source.is_file():
        parser.error("--ingest-source must name the installed dp_ingest.py")
    os.umask(0o077)
    os.environ.setdefault("AWS_DEFAULT_REGION", options.aws_region)
    host = boto3.client("rds", region_name=options.aws_region).describe_db_instances(
        DBInstanceIdentifier=options.db_instance)["DBInstances"][0]["Endpoint"]["Address"]
    os.environ["RHO_DB_HOST"] = host
    os.environ["PGOPTIONS"] = "-c default_transaction_read_only=on -c statement_timeout=60000"
    sys.path.insert(0, str(source.parent))
    spec = importlib.util.spec_from_file_location("auditor_installed_dp_ingest", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    database_url = module.databaseUrl()
    with psycopg.connect(database_url, connect_timeout=10) as connection:
        with connection.cursor() as cursor:
            cursor.execute("SHOW transaction_read_only")
            if cursor.fetchone()[0] != "on":
                raise RuntimeError("auditor database connection is not read-only")

    collect = period_candidate.service.collect

    def collect_with_private_url(args):
        # The existing collector reads this name. Keep it out of the long-lived
        # watcher's environment between short, bounded collection calls.
        previous = os.environ.get("DATABASE_URL")
        os.environ["DATABASE_URL"] = database_url
        try:
            return collect(args)
        finally:
            if previous is None:
                os.environ.pop("DATABASE_URL", None)
            else:
                os.environ["DATABASE_URL"] = previous

    period_candidate.service.collect = collect_with_private_url
    return period_candidate.main(candidate_args)


if __name__ == "__main__":
    raise SystemExit(main())
