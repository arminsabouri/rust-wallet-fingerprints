#!/usr/bin/env bash
set -euo pipefail
LIBNAME=libwallet_fingerprint.so
LINUX_TARGET=x86_64-unknown-linux-gnu

echo "Generating wallet-fingerprint.py..."
# Move to the root directory
cd ../
cargo build --profile release --features ffi
cargo run --profile release \
--features ffi \
--bin uniffi-bindgen generate \
--library target/release/$LIBNAME \
--language python \
--out-dir python/src/wallet-fingerprint/ \

echo "Generating native binaries..."
rustup target add $LINUX_TARGET
cargo build --profile release --target $LINUX_TARGET --features ffi

echo "Copying linux $LIBNAME"
cp target/$LINUX_TARGET/release/$LIBNAME python/src/wallet-fingerprint/$LIBNAME

echo "All done!"
