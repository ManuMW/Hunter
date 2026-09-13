import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Dict, Any, Optional

from src.config import SANDBOX_IMAGE, DETONATION_TIMEOUT, ARTIFACTS_DIR

logger = logging.getLogger(__name__)


def is_docker_available() -> bool:
    """Checks if Docker CLI and daemon are reachable."""
    try:
        res = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        return res.returncode == 0
    except Exception:
        return False


def run_detonation(
    sample_path: str,
    sha256: str,
    timeout_seconds: Optional[int] = None,
    mock_run: bool = False
) -> Dict[str, Any]:
    """
    Executes an untrusted sample inside an ephemeral air-gapped Docker container.
    
    Security Constraints:
    - --network none (strictly isolated, zero WAN access)
    - --memory 512m
    - --cpus 1.0
    - --pids-limit 100 (fork bomb mitigation)
    - --security-opt no-new-privileges
    - Root execution inside container
    """
    timeout = timeout_seconds or DETONATION_TIMEOUT
    run_output_dir = ARTIFACTS_DIR / sha256
    run_output_dir.mkdir(parents=True, exist_ok=True)
    
    # Check if Docker is available
    docker_ready = is_docker_available()
    
    if mock_run or not docker_ready:
        if not docker_ready and not mock_run:
            logger.warning("Docker daemon is not reachable. Falling back to mock detonation mode.")
        return _run_mock_detonation(sample_path, sha256, run_output_dir, timeout)

    with tempfile.TemporaryDirectory() as temp_input:
        temp_input_path = Path(temp_input)
        sandbox_sample = temp_input_path / "sample.bin"
        shutil.copy2(sample_path, sandbox_sample)
        
        # Absolute path resolution (forward slashes for Docker mount compatibility)
        input_mount = str(temp_input_path.resolve()).replace("\\", "/")
        output_mount = str(run_output_dir.resolve()).replace("\\", "/")
        
        cmd = [
            "docker", "run", "--rm",
            "--network", "none",
            "--memory", "512m",
            "--cpus", "1.0",
            "--pids-limit", "100",
            "--security-opt", "no-new-privileges",
            "-e", f"DETONATION_TIMEOUT={timeout}",
            "-v", f"{input_mount}:/sandbox/input:ro",
            "-v", f"{output_mount}:/sandbox/output",
            SANDBOX_IMAGE
        ]
        
        try:
            res = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout + 45  # Grace period for container spin-up and Velociraptor collection
            )
            
            summary_file = run_output_dir / "run_summary.json"
            artifacts_zip = run_output_dir / "artifacts.zip"
            
            run_summary = {}
            if summary_file.exists():
                try:
                    with open(summary_file, "r", encoding="utf-8") as f:
                        run_summary = json.load(f)
                except Exception:
                    pass

            return {
                "status": "completed" if res.returncode == 0 else "failed",
                "exit_code": res.returncode,
                "timeout_seconds": timeout,
                "output_dir": str(run_output_dir),
                "artifacts_zip": str(artifacts_zip) if artifacts_zip.exists() else None,
                "run_summary": run_summary,
                "logs": res.stdout + "\n" + res.stderr
            }
            
        except subprocess.TimeoutExpired as te:
            logger.error(f"Detonation container timed out: {te}")
            return {
                "status": "timed_out",
                "exit_code": -1,
                "timeout_seconds": timeout,
                "output_dir": str(run_output_dir),
                "artifacts_zip": None,
                "run_summary": {"status": "timed_out"},
                "logs": "Execution exceeded maximum allowable watchdog timeout."
            }


def _run_mock_detonation(
    sample_path: str,
    sha256: str,
    output_dir: Path,
    timeout: int
) -> Dict[str, Any]:
    """Generates synthetic forensic artifacts for testing without an active Docker daemon."""
    summary = {
        "start_time": "1726210000",
        "end_time": "1726210090",
        "duration_seconds": timeout,
        "timeout_seconds": timeout,
        "sample_type": "ELF 64-bit LSB executable, x86-64",
        "pid": 1337,
        "status": "completed",
        "mock": True
    }
    
    summary_file = output_dir / "run_summary.json"
    with open(summary_file, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
        
    log_file = output_dir / "detonation.log"
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("[*] Mock detonation execution completed.\n")
        
    # Create simulated triage files
    native_dir = output_dir / "native"
    native_dir.mkdir(exist_ok=True)
    
    with open(native_dir / "processes.txt", "w", encoding="utf-8") as f:
        f.write(
            "root      1337  0.0  0.1  12345  4096 ?  S  14:00  0:00 /sandbox/work/sample\n"
            "root      1338  0.0  0.0   5432  1024 ?  S  14:00  0:00  \\_ /tmp/.hidden_miner -o 198.51.100.23:4444\n"
        )
        
    with open(native_dir / "crontabs.txt", "w", encoding="utf-8") as f:
        f.write("-rw-r--r-- 1 root root 45 Sep 13 14:01 /etc/cron.d/test_persistence\n")
        
    with open(native_dir / "dropped_files.txt", "w", encoding="utf-8") as f:
        f.write("123456  4 -rwxr-xr-x  1 root root  2048 Sep 13 14:00 /tmp/.hidden_miner\n")
        f.write("123457  4 -rw-r--r--  1 root root   128 Sep 13 14:00 /tmp/config.json\n")
        
    # Write actual raw simulated files to dropped/ directory
    dropped_tmp = output_dir / "dropped" / "tmp"
    dropped_tmp.mkdir(parents=True, exist_ok=True)
    
    # Mock ELF binary for .hidden_miner
    with open(dropped_tmp / ".hidden_miner", "wb") as f:
        f.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 200 + b"POOL: 198.51.100.23:4444\x00WALLET: 48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ\x00")
        
    # Mock config.json
    with open(dropped_tmp / "config.json", "w", encoding="utf-8") as f:
        f.write('{\n  "pool": "198.51.100.23:4444",\n  "wallet": "48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ",\n  "pass": "x"\n}\n')
        
    return {
        "status": "completed",
        "exit_code": 0,
        "timeout_seconds": timeout,
        "output_dir": str(output_dir),
        "artifacts_zip": None,
        "run_summary": summary,
        "logs": "[*] Mock detonation completed."
    }
