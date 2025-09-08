#!/bin/sh
set -e

# Install latest yt-dlp at runtime
pip install --no-cache-dir --upgrade yt-dlp

exec "$@"