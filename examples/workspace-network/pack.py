#!/usr/bin/env python3
"""Turn a directory into a workspace manifest, storing every file as a blob.

    python3 examples/workspace-network/pack.py DIR [--root ROOT]

Writes each file under DIR to ROOT/.cairn/blobs/<sha256> (ROOT defaults to the
current directory) and prints {"files": {path: sha256}} on stdout, in the
canonical form: sorted keys, no whitespace. Pack the base tree for the
objective's `base` manifest; pack a submission's directory -- holding only its
editable files, at their tree paths -- for a claim's `files`.

The stand-in for `cairn bench init` until that exists. It writes nothing to the
log and decides nothing; the pinned verifier does that.
"""

import argparse
import hashlib
import json
import os
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("directory")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()

    store = os.path.join(args.root, ".cairn", "blobs")
    os.makedirs(store, exist_ok=True)
    files = {}
    for here, dirs, names in os.walk(args.directory):
        dirs[:] = sorted(d for d in dirs if d not in (".git", "__pycache__"))
        for name in sorted(names):
            full = os.path.join(here, name)
            relative = os.path.relpath(full, args.directory).replace(os.sep, "/")
            with open(full, "rb") as handle:
                data = handle.read()
            address = hashlib.sha256(data).hexdigest()
            with open(os.path.join(store, address), "wb") as handle:
                handle.write(data)
            files[relative] = address
    json.dump({"files": files}, sys.stdout, sort_keys=True, separators=(",", ":"))


main()
