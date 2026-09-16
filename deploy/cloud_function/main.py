import json
import logging
from typing import Tuple, Dict, Any
import functions_framework
from googleapiclient import discovery
import google.auth

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wake_host")

PROJECT = "stockbot-scheduled"
ZONE = "asia-south1-b"
INSTANCE = "velociraptor"

CORS_HEADERS = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, ngrok-skip-browser-warning",
    "Access-Control-Max-Age": "3600"
}

@functions_framework.http
def wake_host(request) -> Tuple[str, int, Dict[str, str]]:
    """HTTP Cloud Function to check and wake up the Velociraptor detonation VM."""
    if request.method == "OPTIONS":
        return ("", 204, CORS_HEADERS)

    try:
        credentials, _ = google.auth.default()
        compute = discovery.build("compute", "v1", credentials=credentials, cache_discovery=False)
        
        # Check current status
        instance = compute.instances().get(project=PROJECT, zone=ZONE, instance=INSTANCE).execute()
        current_status = instance.get("status", "UNKNOWN")
        logger.info(f"[*] Instance {INSTANCE} current status: {current_status}")

        if current_status in ["TERMINATED", "STOPPED"]:
            logger.info(f"[+] Sending START signal to {INSTANCE}...")
            operation = compute.instances().start(project=PROJECT, zone=ZONE, instance=INSTANCE).execute()
            response_payload = {
                "status": "booting",
                "instance": INSTANCE,
                "previous_state": current_status,
                "message": "Cloud Detonation Host is booting up. Expected online in ~20 seconds.",
                "operation": operation.get("name")
            }
            return (json.dumps(response_payload), 200, {**CORS_HEADERS, "Content-Type": "application/json"})
        
        elif current_status == "RUNNING":
            response_payload = {
                "status": "running",
                "instance": INSTANCE,
                "message": "Cloud Detonation Host is already running and operational."
            }
            return (json.dumps(response_payload), 200, {**CORS_HEADERS, "Content-Type": "application/json"})
        
        else:
            response_payload = {
                "status": "transitioning",
                "instance": INSTANCE,
                "current_state": current_status,
                "message": f"Cloud Detonation Host is currently {current_status}."
            }
            return (json.dumps(response_payload), 200, {**CORS_HEADERS, "Content-Type": "application/json"})

    except Exception as e:
        logger.error(f"[-] Error querying or starting instance: {e}", exc_info=True)
        return (json.dumps({"status": "error", "error": str(e)}), 500, {**CORS_HEADERS, "Content-Type": "application/json"})
