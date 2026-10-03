import subprocess
import json
import time
import sys

TARGET_HASH = sys.argv[1] if len(sys.argv) > 1 else "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96"

def start_vm():
    print("[*] Checking VM status...")
    check_cmd = [
        "gcloud", "compute", "instances", "describe", "velociraptor",
        "--zone=asia-south1-b",
        "--project=stockbot-scheduled",
        "--format=value(status)"
    ]
    res = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
    status = res.stdout.strip()
    print(f"[*] Current status: {status}")
    if status != "RUNNING":
        print("[*] Starting VM...")
        start_cmd = [
            "gcloud", "compute", "instances", "start", "velociraptor",
            "--zone=asia-south1-b",
            "--project=stockbot-scheduled"
        ]
        subprocess.run(start_cmd, capture_output=True, text=True, shell=True)
        for i in range(15):
            time.sleep(5)
            res = subprocess.run(check_cmd, capture_output=True, text=True, shell=True)
            if res.stdout.strip() == "RUNNING":
                print("[+] VM is now RUNNING. Settling for 10s...")
                time.sleep(10)
                break

def run_ssh(remote_cmd, timeout=120, max_retries=3):
    cmd = [
        "gcloud", "compute", "ssh", "manumw21@velociraptor",
        "--zone=asia-south1-b",
        "--project=stockbot-scheduled",
        "--tunnel-through-iap",
        f"--command={remote_cmd}",
        "--", "-batch"
    ]
    print(f"[*] Executing on VM: {remote_cmd}")
    for attempt in range(max_retries):
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
        if res.returncode == 0:
            print("[+] Output:\n", res.stdout)
            return res
        print(f"[-] Attempt {attempt+1}/{max_retries} failed with code {res.returncode}. Retrying in 5s...")
        time.sleep(5)
    print("STDOUT:", res.stdout)
    print("STDERR:", res.stderr)
    return res

def main():
    start_vm()

    print(f"[*] Target Sample: {TARGET_HASH}")
    print("[1/5] Updating code on VM and ensuring dependencies...")
    setup_cmd = (
        "cd /home/manumw21/Hunter && "
        "git pull origin main && "
        "/home/manumw21/Hunter/.venv/bin/pip install pyelftools && "
        "sudo systemctl restart hunter-detonation"
    )
    res = run_ssh(setup_cmd)
    if res.returncode != 0:
        print("[-] Setup failed!")
        return

    print("[2/5] Waiting 5s for service to settle...")
    time.sleep(5)

    print(f"[3/5] Submitting hash {TARGET_HASH} to detonation API...")
    admin_client_id = f"admin-runner-{int(time.time())}"
    submit_cmd = (
        f"curl -s -X POST http://127.0.0.1:8888/api/submit-hash "
        f"-H 'Content-Type: application/json' "
        f"-H 'X-Client-Id: {admin_client_id}' "
        f"-d '{{\"sha256\": \"{TARGET_HASH}\"}}'"
    )
    res = run_ssh(submit_cmd)
    task_id = None
    try:
        data = json.loads(res.stdout.strip())
        task_id = data.get("task_id")
        print(f"[+] Task ID: {task_id}, Status: {data.get('status')}")
    except Exception as e:
        print(f"[-] Could not parse JSON response: {e}")

    if not task_id:
        print(f"[-] Submission failed: {res.stdout.strip()}")
        return

    print("[4/5] Polling task status...")
    for i in range(35):
        time.sleep(10)
        if task_id:
            check_cmd = f"curl -s http://127.0.0.1:8888/api/tasks/{task_id}"
            res = run_ssh(check_cmd, timeout=30)
            try:
                tdata = json.loads(res.stdout.strip())
                status = tdata.get("status")
                print(f"[*] Task status: {status}")
                if status == "completed":
                    print("[+] Detonation completed successfully!")
                    break
                elif status == "failed":
                    print(f"[-] Detonation failed: {tdata.get('error')}")
                    break
            except Exception:
                pass
        else:
            check_cmd = "sudo journalctl -u hunter-detonation -n 20 --no-pager"
            res = run_ssh(check_cmd, timeout=30)

    print(f"[5/5] Checking final report on VM for {TARGET_HASH}...")
    verify_cmd = f"head -n 60 /home/manumw21/Hunter/reports/{TARGET_HASH}.md"
    run_ssh(verify_cmd)

if __name__ == "__main__":
    main()
