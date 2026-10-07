#!/usr/bin/env bash
# Runs the full scenario harness against the compose stack (normal mode, then test mode).
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== normal mode"
docker compose up --build --wait --wait-timeout 120
docker exec -i croa-pilot-001-c6_firewall-1 python - < tests/test_phase5.py
docker exec -i croa-pilot-001-croa_plane-1 python - < tests/test_phase3.py
docker exec -i croa-pilot-001-croa_plane-1 python - < tests/test_ttl_enforcement.py

echo "== test mode"
docker compose down
docker compose -f docker-compose.yml -f docker-compose.test.yml up --wait --wait-timeout 120
docker exec -i croa-pilot-001-c6_firewall-1 python - < tests/test_phase4.py
docker exec -i croa-pilot-001-croa_plane-1 python - < tests/test_hardening.py

echo "== restoring normal mode"
docker compose down
docker compose up -d
