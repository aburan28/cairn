# syntax=docker/dockerfile:1
#
# The number-theory toolchain the crypto-autoresearcher GFPN experiments
# record in their run manifests: PARI/GP 2.15.4 with the SEA data, msolve
# 0.6.5 and valgrind 3.22.0 (Ubuntu 24.04 ships exactly these, so they are
# pinned to the archive's builds), plus python-flint 0.9.0, cypari2 2.2.0,
# numpy 2.4.6 and pyyaml 6.0.1 in a venv at /opt/py.
#
# One honest gap: those runs used CPython 3.11.15, which no longer has a
# package anybody serves for 24.04. This uses the distribution's python3. The
# environment's tree digest records exactly what is inside, so a protocol
# that pins the interpreter's patch version will notice rather than be fooled.
#
# Build with examples/lab/environments/build.sh numtheory, then
#   cairn lab env import numtheory --docker cairn-lab/numtheory:latest --identity ID
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
        pari-gp=2.15.4-2.1build1 pari-seadata msolve=0.6.5-1build2 \
        valgrind python3 python3-venv ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# The CA secret exists only where outbound TLS is re-terminated by a proxy;
# everywhere else it is absent and pip uses the system store.
RUN --mount=type=secret,id=ca,required=false \
    set -e; \
    if [ -s /run/secrets/ca ]; then export PIP_CERT=/run/secrets/ca; fi; \
    python3 -m venv /opt/py; \
    /opt/py/bin/pip install --no-cache-dir \
        python-flint==0.9.0 cypari2==2.2.0 numpy==2.4.6 pyyaml==6.0.1

ENV PATH=/opt/py/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /out
