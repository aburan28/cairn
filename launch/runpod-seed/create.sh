#!/bin/sh
# Rent the seed, or print the pod that would be rented.
# See README.md. RUNPOD_API_KEY is required except for --dry-run.
cd "$(dirname "$0")"
exec python3 ./create.py "$@"
