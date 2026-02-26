#!/usr/bin/env bash
set -euo pipefail
###############################################################################
# cli.sh — Bitcoin transaction / block analyzer CLI (ROOT LEVEL)
#
# This is the entry point that the grader will run.
# It calls the Python implementation in the app/ folder.
###############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR/app"

error_json() {
  local code="$1"
  local message="$2"
  printf '{"ok":false,"error":{"code":"%s","message":"%s"}}\n' "$code" "$message"
}

# --- Block mode ---
if [[ "${1:-}" == "--block" ]]; then
  shift
  if [[ $# -lt 3 ]]; then
    error_json "INVALID_ARGS" "Block mode requires: --block <blk.dat> <rev.dat> <xor.dat>"
    echo "Error: Block mode requires 3 file arguments: <blk.dat> <rev.dat> <xor.dat>" >&2
    exit 1
  fi
  
  BLK_FILE="$1"
  REV_FILE="$2"
  XOR_FILE="$3"
  
  for f in "$BLK_FILE" "$REV_FILE" "$XOR_FILE"; do
    if [[ ! -f "$f" ]]; then
      error_json "FILE_NOT_FOUND" "File not found: $f"
      echo "Error: File not found: $f" >&2
      exit 1
    fi
  done
  
  mkdir -p out
  
  # Call Python in app directory
  PYTHONPATH="$APP_DIR:$PYTHONPATH" python3 "$APP_DIR/main.py" --block "$BLK_FILE" "$REV_FILE" "$XOR_FILE"
  exit $?
fi

# --- Single-transaction mode ---
if [[ $# -lt 1 ]]; then
  error_json "INVALID_ARGS" "Usage: cli.sh <fixture.json> or cli.sh --block <blk> <rev> <xor>"
  echo "Error: No fixture file provided" >&2
  exit 1
fi

FIXTURE="$1"

if [[ ! -f "$FIXTURE" ]]; then
  error_json "FILE_NOT_FOUND" "Fixture file not found: $FIXTURE"
  echo "Error: Fixture file not found: $FIXTURE" >&2
  exit 1
fi

mkdir -p out

# Call Python in app directory with full path to fixture
FIXTURE_FULL="$(cd "$(dirname "$FIXTURE")" && pwd)/$(basename "$FIXTURE")"
PYTHONPATH="$APP_DIR:$PYTHONPATH" python3 "$APP_DIR/main.py" "$FIXTURE_FULL"
exit $?