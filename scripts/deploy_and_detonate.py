import subprocess
import json
import time
import sys

def run_ssh(remote_cmd, timeout=120):
    cmd = [
        "gcloud", "compute", "ssh", "manumw21@velociraptor",
        "--zone=asia-south1-b",
        "--project=stockbot-scheduled",
        "--tunnel-through-iap",
        f"--command={remote_cmd}",
        "--", "-batch"
    ]
    print(f"[*] Executing on VM: {remote_cmd}")
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, shell=True)
    if res.returncode != 0:
        print(f"[-] Command failed with code {res.returncode}")
        print("STDOUT:", res.stdout)
        print("STDERR:", res.stderr)
    else:
        print("[+] Output:\n", res.stdout)
    return res

def main():
    print("[1/5] Updating code on VM and ensuring dependencies...")
    setup_cmd = (
        "cd /home/manumw21/Hunter && "
        "git pull origin main && "
        "/home/manumw21/Hunter/.venv/bin/pip install pyelftools && "
        "sed -i 's/gemini-3.6-flash/gemini-2.5-flash/g' .env && "
        "grep GEMINI_MODEL .env && "
        "sudo systemctl restart hunter-detonation"
    )
    res = run_ssh(setup_cmd)
    if res.returncode != 0:
        print("[-] Setup failed!")
        return

    print("[2/5] Waiting 5s for service to settle...")
    time.sleep(5)

    print("[3/5] Cleaning old report and submitting hash...")
    submit_cmd = (
        "rm -f /home/manumw21/Hunter/reports/e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c.md && "
        "curl -s -X POST http://127.0.0.1:8888/api/submit-hash "
        "-H 'Content-Type: application/json' "
        "-d '{\"sha256\": \"e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c\"}'"
    )
    res = run_ssh(submit_cmd)
    try:
        data = json.loads(res.stdout.strip())
        task_id = data.get("task_id")
        print(f"[+] Task ID: {task_id}, Status: {data.get('status')}")
    except Exception as e:
        print(f"[-] Could not parse JSON response: {e}")
        task_id = None

    print("[4/5] Polling task status...")
    for i in range(30):
        time.sleep(10)
        if task_id:
            check_cmd = f"curl -s http://127.0.0.1:8888/api/task/{task_id}"
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

    print("[5/5] Checking final report on VM...")
    verify_cmd = "head -n 60 /home/manumw21/Hunter/reports/e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c.md"
    run_ssh(verify_cmd)

if __name__ == "__main__":
    main()
