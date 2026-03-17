#!/bin/bash
# Run the installer. From repo root: ./install.sh [--install] [--prefix DIR]
cd "$(dirname "$0")"
exec ./scripts/install.sh "$@"
