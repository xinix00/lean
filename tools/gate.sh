#!/bin/sh
# De poort (handboek §9): host-tests, clippy met de harde set, rustfmt, en de
# no_std-bouw voor het target. Rood is rood.
set -e
cd "$(dirname "$0")/.."
echo "== host: cargo test"
cargo test --quiet
echo "== host: cargo clippy"
cargo clippy --all-targets --quiet -- -D warnings
echo "== rustfmt"
cargo fmt --check
echo "== target: no_std (aarch64)"
cargo build --quiet --target aarch64-unknown-none-softfloat
echo "poort groen"
