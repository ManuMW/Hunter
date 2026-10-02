#!/usr/bin/env python3
"""
Hunter Security Labs - Cloud Detonation Host Idle Watchdog
Polls API health check and gracefully shuts down VM (/sbin/poweroff)
after IDLE_LIMIT_SECONDS of continuous inactivity.
Tracks both queued_tasks and active_tasks.
"""
import time
import subprocess
import urllib.request
import json
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("hunter-watchdog")

IDLE_LIMIT_SECONDS = 300
CHECK_INTERVAL_SECONDS = 30
API_URL = "http://127.0.0.1:8888/health"

logger.info("[*] Hunter Inactivity Watchdog started. Grace period: 3m. Idle timeout: 5m.")
time.sleep(180)
idle_start = time.time()

while True:
    time.sleep(CHECK_INTERVAL_SECONDS)
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "HunterWatchdog/1.0"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode())
            queued = data.get("queued_tasks", 0)
            active = data.get("active_tasks", 0)

            if queued == 0 and active == 0:
                elapsed = int(time.time() - idle_start)
                logger.info(f"[*] Pipeline idle (queued: {queued}, active: {active}). Inactive for {elapsed}s / {IDLE_LIMIT_SECONDS}s.")
                if elapsed >= IDLE_LIMIT_SECONDS:
                    logger.warning("[!] Inactivity threshold reached! Auto-shutting down Cloud VM...")
                    subprocess.run(["/sbin/poweroff"])
                    break
            else:
                logger.info(f"[*] Pipeline active (active: {active}, queued: {queued}). Resetting idle timer.")
                idle_start = time.time()
    except Exception as e:
        logger.warning(f"[-] Health check error: {e}")
