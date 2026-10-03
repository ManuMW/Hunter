import subprocess
import time
import sys

print("[*] Starting velociraptor...")
start_res = subprocess.run([
    "gcloud", "compute", "instances", "start", "velociraptor",
    "--zone=asia-south1-b", "--project=stockbot-scheduled"
], capture_output=True, text=True, shell=True)
print(start_res.stdout.strip())

print("[*] Waiting 15 seconds for SSH to become ready...")
time.sleep(15)

remote_cmd = (
    "echo '=== REPORTS DIR ===' && "
    "ls -la /home/manumw21/Hunter/reports/ && "
    "echo '=== GIT STATUS ===' && "
    "cd /home/manumw21/Hunter && git status && "
    "echo '=== RECENT DETONATION LOGS ===' && "
    "sudo journalctl -u hunter-detonation -b -1 -n 60 --no-pager"
)

cmd = [
    "gcloud", "compute", "ssh", "manumw21@velociraptor",
    "--zone=asia-south1-b",
    "--project=stockbot-scheduled",
    f"--command={remote_cmd}",
    "--", "-batch"
]

print("[*] Connecting via SSH...")
ssh_res = subprocess.run(cmd, capture_output=True, text=True, timeout=90, shell=True)
print("STDOUT:\n" + ssh_res.stdout.strip())
if ssh_res.stderr:
    print("STDERR:\n" + ssh_res.stderr.strip())
