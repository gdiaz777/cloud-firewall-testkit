#!/bin/bash
# Rebuilds the catalog (and its docs) and the image:  ./build.sh [tag=cloud-firewall-testkit:local]
set -euo pipefail
cd "$(dirname "$0")"
python3 catalog/catalog.py catalog/tests.json && python3 catalog/gen_docs.py
docker build -t "${1:-cloud-firewall-testkit:local}" .
