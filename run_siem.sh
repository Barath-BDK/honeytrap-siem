#!/usr/bin/env bash
# Starts the pipeline (log puller + detection engine) and the dashboard together.
set -e
cd "$(dirname "$0")/siem"
[ -d ../venv ] && source ../venv/bin/activate
python pipeline.py &
PIPE=$!
trap 'kill $PIPE 2>/dev/null' EXIT
python app.py
