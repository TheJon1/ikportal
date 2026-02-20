#!/usr/bin/env bash
set -e

# Render varsayılan PORT değişkenini verir
exec gunicorn -b 0.0.0.0:${PORT} app:app
