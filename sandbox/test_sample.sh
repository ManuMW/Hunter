#!/usr/bin/env bash
# Benign simulation script to test forensic artifact extraction
echo "[Simulation] Starting test sample execution..."

# 1. Simulate dropped payload in /tmp
echo "[Simulation] Dropping secondary file in /tmp..."
mkdir -p /tmp/.hidden_test
cat <<EOF > /tmp/.hidden_test/miner_config.json
{
  "pool": "198.51.100.23:4444",
  "wallet": "48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ",
  "pass": "x"
}
EOF

# 2. Simulate persistence in cron
echo "[Simulation] Simulating persistence hook..."
mkdir -p /etc/cron.d
echo "* * * * * root /tmp/.hidden_test/run.sh" > /etc/cron.d/test_persistence 2>/dev/null || true

# 3. Simulate process activity
echo "[Simulation] Spawning child sleep process..."
sleep 5 &

echo "[Simulation] Test sample finished execution steps."
exit 0
