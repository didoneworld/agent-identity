#!/usr/bin/env sh
set -eu

cd /app
python -m pytest tests/test_examples.py "$@"
