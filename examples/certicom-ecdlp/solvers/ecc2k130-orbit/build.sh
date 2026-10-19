#!/bin/sh
# Rebuild bin/ from src/main.rs, then re-pack the package.
#
# The binaries are committed because the package id pins their bytes: a node
# offers, and a contributor runs, exactly the files solver.json names. This is
# how they were made, so anyone can rebuild them and compare hashes.
#
#   darwin-arm64   rustc, -C target-cpu=apple-m1 (every Apple silicon Mac)
#   linux-x86_64   rustc, x86_64-unknown-linux-musl, linked by rust-lld with
#                  Rust's own musl: static, no C toolchain. x86-64-v2 plus
#                  PCLMULQDQ (every x86-64 CPU since 2010); the binary refuses
#                  a CPU without it rather than faulting.
#
# One file, the standard library, no crates: nothing to vendor or fetch.
#
#   rustup toolchain install 1.98.0 --target aarch64-apple-darwin,x86_64-unknown-linux-musl
#   examples/certicom-ecdlp/solvers/ecc2k130-orbit/build.sh
set -eu

here=$(cd "$(dirname "$0")" && pwd)
toolchain=${RUST_TOOLCHAIN:-1.98.0}
want="rustc 1.98.0 "
rustc() { rustup run "$toolchain" rustc "$@"; }

have=$(rustc --version)
case "$have" in
  "$want"*) ;;
  *)
    echo "build.sh: $have is not the toolchain the committed binaries came from ($want)." >&2
    echo "          Their bytes, and so the package id, will change. Set RUST_TOOLCHAIN to override." >&2
    [ "${RUST_TOOLCHAIN:-}" ] || exit 2
    ;;
esac

cd "$here"
mkdir -p bin
common="--edition 2021 -C opt-level=3 -C codegen-units=1 -C panic=abort -C debuginfo=0 -C strip=symbols --remap-path-prefix=$here=."

rustc $common --target aarch64-apple-darwin -C target-cpu=apple-m1 \
  src/main.rs -o bin/ecc2k130-orbit-darwin-arm64

rustc $common --target x86_64-unknown-linux-musl \
  -C target-cpu=x86-64-v2 -C target-feature=+pclmulqdq,+crt-static \
  -C linker=rust-lld -C linker-flavor=ld.lld -C link-self-contained=yes \
  src/main.rs -o bin/ecc2k130-orbit-linux-x86_64

shasum -a 256 bin/*
echo "now: cairn solver pack $here" >&2
