echo "Running test_phase4.py"
docker compose -f docker-compose.yml -f docker-compose.test.yml up -d
cat tests/test_phase4.py | docker exec -i croa-pilot-001-c6_firewall-1 python -
echo "EXIT: $?"
docker compose down
docker compose up -d

sleep 3
echo "Running test_phase5.py"
cat tests/test_phase5.py | docker exec -i croa-pilot-001-c6_firewall-1 python -
echo "EXIT: $?"

echo "Running test_ttl_enforcement.py"
cat tests/test_ttl_enforcement.py | docker exec -i croa-pilot-001-c6_firewall-1 python -
echo "EXIT: $?"

echo "Running test_hardening.py"
cat tests/test_hardening.py | docker exec -i croa-pilot-001-croa_plane-1 python -
echo "EXIT: $?"
