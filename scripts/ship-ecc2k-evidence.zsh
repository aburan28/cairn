#!/bin/zsh
set -euo pipefail

export AWS_PROFILE=ecc2k130
export AWS_DEFAULT_REGION=us-west-2

source_dir="$HOME/Library/Application Support/ECC2K130/ingest/evidence/macbook-publisher"
destination='s3://ecc2k130-590183823895/logs/rho-ingest-macbook-publisher/evidence/'

# Archived journals and content-addressed snapshots are durable; the live
# period and lock are mutable supervisor state and must never be copied.
/opt/homebrew/bin/aws s3 sync "$source_dir/" "$destination" \
  --exclude 'current-period.json' \
  --exclude 'operator.lock' \
  --only-show-errors
