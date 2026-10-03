import subprocess
import sys

remote_cmd = "cd /home/manumw21/Hunter && git pull origin main && git log -n 1 --oneline && sudo systemctl restart hunter-detonation"

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
