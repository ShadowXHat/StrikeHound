#!/bin/bash
#
# StrikeHound convenience wrapper.
#
# Instead of remembering to activate the venv and call strikehound.py
# with all its flags, just run:
#
#   ./scan.sh <target> [mode] [extra strikehound.py flags...]
#
# Examples:
#   ./scan.sh http://example.com
#   ./scan.sh http://example.com full
#   ./scan.sh http://example.com standard --no-report
#
set -e

if [ -z "$1" ]; then
    echo "Usage: ./scan.sh <target> [mode: quick|standard|full] [extra flags...]"
    echo "Example: ./scan.sh http://example.com quick"
    exit 1
fi

if [ ! -d venv ]; then
    echo "[!] Virtual environment not found. Run ./setup.sh first."
    exit 1
fi

TARGET="$1"
MODE="${2:-standard}"
shift
if [ -n "$1" ]; then shift; fi  # drop MODE from the arg list if it was given

# shellcheck disable=SC1091
source venv/bin/activate
python3 strikehound.py -t "$TARGET" -m "$MODE" "$@"
