#!/bin/bash
# Build release and copy binary into versioned folder (e.g. 0.1.3/).
# Run from project root: ./scripts/build-release.sh
set -e
cd "$(dirname "$0")/.."
VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/' | tr -d ' ')
echo "Building rust-dns v${VERSION}..."
cargo build --release
mkdir -p "$VERSION"
cp target/release/rust-dns "$VERSION/"
echo "Done: $VERSION/rust-dns"
"$VERSION/rust-dns" --version 2>/dev/null || true
