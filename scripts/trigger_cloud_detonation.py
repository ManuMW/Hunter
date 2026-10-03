import subprocess
import sys

remote_cmd = "sqlite3 /home/manumw21/Hunter/data/hunter.db 'SELECT * FROM client_quotas;'"

cmd = [
    "gcloud", "compute", "ssh", "manumw21@velociraptor",
    "--zone=asia-south1-b",
    "--project=stockbot-scheduled",
    "--tunnel-through-iap",
    f"--command={remote_cmd}",
    "--", "-batch"
]

print("[*] Inspecting traceback...")
res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, shell=True)
print(res.stdout.strip())
if res.stderr:
    print("STDERR:", res.stderr.strip())
sys.exit(res.returncode)
