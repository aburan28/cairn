# syntax=docker/dockerfile:1
#
# The numtheory environment plus SageMath 10.9 from conda-forge, installed at
# /opt/conda-sage/envs/sage — the path the GFPN anchor comparator calls
# (`SAGE_PYTHON = "/opt/conda-sage/envs/sage/bin/python"` in its
# implementation). A host without that path is exactly how a gate package
# failed with `infrastructure_error`; inside this environment the path exists.
#
# Sage's bin directory is appended to PATH, not prepended, so `python3` stays
# the numtheory venv's and the comparator still reaches Sage by its full path.
#
# Build with examples/lab/environments/build.sh sage (it builds numtheory
# first), then
#   cairn lab env import sage --docker cairn-lab/sage:latest --identity ID
ARG BASE=cairn-lab/numtheory:latest
FROM ${BASE}

ARG SAGE_VERSION=10.9
ARG MICROMAMBA_VERSION=2.3.2-0
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl bzip2 \
 && rm -rf /var/lib/apt/lists/*

RUN --mount=type=secret,id=ca,required=false \
    set -e; \
    CA=""; if [ -s /run/secrets/ca ]; then CA=/run/secrets/ca; fi; \
    curl -fsSL ${CA:+--cacert "$CA"} -o /usr/local/bin/micromamba \
        "https://github.com/mamba-org/micromamba-releases/releases/download/${MICROMAMBA_VERSION}/micromamba-linux-64"; \
    chmod +x /usr/local/bin/micromamba; \
    export MAMBA_ROOT_PREFIX=/opt/conda-sage; \
    micromamba create -y -p /opt/conda-sage/envs/sage -c conda-forge \
        ${CA:+--cacert-path "$CA"} "sage=${SAGE_VERSION}"; \
    micromamba clean --all --yes; \
    rm -rf /opt/conda-sage/pkgs /root/.cache

ENV PATH=/opt/py/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/conda-sage/envs/sage/bin
WORKDIR /out
