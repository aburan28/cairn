#!/bin/sh
# Build the Sage environment's root filesystem without docker.
#
#   build-rootfs.sh BASE_ROOTFS OUT_DIR
#   cairn lab env import sage --dir OUT_DIR --move --identity ID
#
# BASE_ROOTFS is the numtheory environment's tree (`cairn lab env show
# numtheory` names it; it lives under the lab's envs/). The script copies it,
# then installs SageMath with micromamba *inside* bubblewrap, so the conda
# prefix baked into every installed file is the path the environment will
# have when it runs — /opt/conda-sage/envs/sage — and not a host path.
#
# Why this exists beside the Dockerfile: a docker build of a multi-gigabyte
# conda layer holds it two or three times over (build snapshot, exported
# layer, unpacked image) before `cairn lab env import --docker` copies it once
# more. This holds it once, and `--move` hands that one copy to the lab.
#
# Behind a TLS-re-terminating proxy, set HTTPS_PROXY and CAIRN_BUILD_CA (or
# SSL_CERT_FILE); bubblewrap shares the host network so a proxy on 127.0.0.1
# is reachable.
set -eu

base="${1:?usage: build-rootfs.sh BASE_ROOTFS OUT_DIR}"
out="${2:?usage: build-rootfs.sh BASE_ROOTFS OUT_DIR}"
sage_version="${SAGE_VERSION:-10.9}"
mamba_version="${MICROMAMBA_VERSION:-2.3.2-0}"

if [ -e "$out" ]; then
    echo "$out already exists; refusing to build over it" >&2
    exit 2
fi
command -v bwrap >/dev/null || { echo "needs bubblewrap (bwrap)" >&2; exit 2; }

mkdir -p "$out"
cp -a "$base/." "$out/"

ca="${CAIRN_BUILD_CA:-${SSL_CERT_FILE:-}}"
mkdir -p "$out/usr/local/bin"
curl -fsSL ${ca:+--cacert "$ca"} -o "$out/usr/local/bin/micromamba" \
    "https://github.com/mamba-org/micromamba-releases/releases/download/${mamba_version}/micromamba-linux-64"
chmod +x "$out/usr/local/bin/micromamba"

set --
if [ -n "$ca" ] && [ -s "$ca" ]; then
    cp "$ca" "$out/.build-ca.pem"
    set -- --cacert-path /.build-ca.pem
fi

run() {
    bwrap --bind "$out" / --proc /proc --dev /dev --tmpfs /tmp --share-net \
        --ro-bind-try /etc/resolv.conf /etc/resolv.conf \
        --setenv PATH /usr/local/bin:/usr/bin:/bin \
        --setenv MAMBA_ROOT_PREFIX /opt/conda-sage \
        ${HTTPS_PROXY:+--setenv HTTPS_PROXY "$HTTPS_PROXY"} \
        -- "$@"
}

run /usr/local/bin/micromamba create -y -p /opt/conda-sage/envs/sage -c conda-forge "$@" "sage=${sage_version}"
run /usr/local/bin/micromamba clean --all --yes
rm -rf "$out/opt/conda-sage/pkgs" "$out/.build-ca.pem" "$out/root/.cache"

echo
echo "built $out"
echo "next: cairn lab env import sage --dir $out --move --identity YOUR.identity.json \\"
echo "        --env PATH=/opt/py/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/opt/conda-sage/envs/sage/bin"
