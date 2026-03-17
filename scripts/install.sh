#!/bin/bash
# Install rust-dns from source. Run from anywhere.
#
# One-liner:
#   bash -c "$(curl -sSfL https://raw.githubusercontent.com/ZeroXShazam/dnspesctor/main/scripts/install.sh)"
# Or clone then run:
#   git clone https://github.com/ZeroXShazam/dnspesctor.git && cd dnspesctor && ./scripts/install.sh
#
# Options:
#   --install    Copy binary to ~/.local/bin (or PREFIX/bin if PREFIX is set)
#   --prefix DIR Use DIR instead of ~/.local for install
set -e

RUST_DNS_REPO="${RUST_DNS_REPO:-https://github.com/ZeroXShazam/dnspesctor.git}"
INSTALL_TO_PATH=false
PREFIX="${PREFIX:-$HOME/.local}"

while [ $# -gt 0 ]; do
  case "$1" in
    --install) INSTALL_TO_PATH=true; shift ;;
    --prefix)  PREFIX="$2"; shift 2 ;;
    *) break ;;
  esac
done

if ! command -v cargo >/dev/null 2>&1; then
  echo "Rust/cargo not found. Install from https://rustup.rs/:"
  echo "  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
  exit 1
fi

if [ -f "Cargo.toml" ] && grep -q 'name = "rust-dns"' Cargo.toml 2>/dev/null; then
  SRC="$(pwd)"
  echo "Using existing repo: $SRC"
else
  TMP="${TMPDIR:-/tmp}/rust-dns-install.$$"
  mkdir -p "$TMP"
  trap "rm -rf '$TMP'" EXIT
  echo "Cloning $RUST_DNS_REPO..."
  git clone --depth 1 "$RUST_DNS_REPO" "$TMP/dnspesctor"
  SRC="$TMP/dnspesctor"
fi

cd "$SRC"
./scripts/build-release.sh

if [ "$INSTALL_TO_PATH" = true ]; then
  BINDIR="$PREFIX/bin"
  mkdir -p "$BINDIR"
  VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/version = "\(.*\)"/\1/' | tr -d ' ')
  cp "$VERSION/rust-dns" "$BINDIR/"
  echo "Installed: $BINDIR/rust-dns"
  if ! echo "$PATH" | grep -q "$BINDIR"; then
    echo "Add to PATH: export PATH=\"$BINDIR:\$PATH\""
  fi
fi
