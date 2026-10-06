#!/bin/sh
# Stop the bill. Deletes the pod named cairn-seed (or CAIRN_SEED_NAME).
cd "$(dirname "$0")"
exec python3 ./create.py --down --yes "$@"
