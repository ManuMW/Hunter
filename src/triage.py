import hashlib
import json
import logging
import re
import zipfile
from pathlib import Path
from typing import Dict, Any, List

from src.quarantine import detect_file_type, quarantine_sample

logger = logging.getLogger(__name__)

# Baseline processes to filter out from noise
BASELINE_PROCESS_NAMES = {
    "systemd", "kthreadd", "rcu_gp", "kworker", "bash", "sh",
    "entrypoint.sh", "velociraptor", "ps", "sleep", "pgrep", "pkill"
}


def extract_printable_strings(content: bytes, min_len: int = 4) -> List[str]:
    """Extracts printable ASCII strings and isolates suspicious indicators."""
    pattern = rb"[ -~]{" + str(min_len).encode() + rb",}"
    matches = re.findall(pattern, content)
    strings = [m.decode("ascii", errors="ignore") for m in matches]
    interesting = []
    for s in strings:
        if any(marker in s for marker in [":", "/", ".", "http", "pool", "miner", "wallet", "cron", "bash", "root"]):
            if s not in interesting:
                interesting.append(s)
    return interesting[:30] if interesting else strings[:20]


def analyze_dropped_payloads(output_dir: Path) -> List[Dict[str, Any]]:
    """
    Discovers, hashes, and statically inspects raw dropped files exported from the sandbox.
    Automatically registers executable binaries into the Quarantine Store for standalone detonation.
    """
    dropped_dir = output_dir / "dropped"
    payloads = []
    if not dropped_dir.exists():
        return payloads

    for file_path in dropped_dir.rglob("*"):
        if file_path.is_file():
            try:
                content = file_path.read_bytes()
                sha256 = hashlib.sha256(content).hexdigest()
                md5 = hashlib.md5(content).hexdigest()
                file_type = detect_file_type(content[:1024])
                rel_path = "/" + str(file_path.relative_to(dropped_dir)).replace("\\", "/")

                parsed_content = None
                if file_path.suffix == ".json" or content.strip().startswith(b"{"):
                    try:
                        parsed_content = json.loads(content.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass

                # If binary or script, automatically quarantine for standalone detonation
                if "ELF" in file_type or "Script" in file_type or file_path.name.startswith("."):
                    quarantine_sample(content, file_path.name)

                payloads.append({
                    "filename": file_path.name,
                    "target_path": rel_path,
                    "sha256": sha256,
                    "md5": md5,
                    "size_bytes": len(content),
                    "file_type": file_type,
                    "extracted_strings": extract_printable_strings(content),
                    "parsed_config": parsed_content
                })
            except Exception as e:
                logger.warning(f"Failed to inspect dropped file {file_path}: {e}")

    return payloads


def parse_native_processes(content: str) -> List[Dict[str, str]]:
    """Parses ps aux output into structured process entries, filtering baseline noise."""
    processes = []
    lines = content.strip().splitlines()
    for line in lines[1:]:  # Skip header
        parts = line.split(None, 10)
        if len(parts) >= 11:
            cmd = parts[10].strip()
            # Filter standard system noise
            if any(base in cmd for base in BASELINE_PROCESS_NAMES):
                continue
            processes.append({
                "user": parts[0],
                "pid": parts[1],
                "cpu": parts[2],
                "mem": parts[3],
                "command": cmd
            })
    return processes


def parse_native_dropped_files(content: str) -> List[Dict[str, str]]:
    """Parses find/ls output for dropped files, ignoring standard directory markers."""
    files = []
    for line in content.strip().splitlines():
        parts = line.split()
        if len(parts) >= 9:
            path = parts[-1]
            if path in ["/tmp", "/tmp/.", "/tmp/..", "/var/tmp", "/dev/shm"]:
                continue
            files.append({
                "permissions": parts[2] if len(parts) > 2 else "",
                "size": parts[6] if len(parts) > 6 else "",
                "path": path
            })
    return files


def parse_native_crontabs(content: str) -> List[str]:
    """Extracts non-empty lines from crontab outputs."""
    entries = []
    for line in content.strip().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "total " not in line:
            entries.append(line)
    return entries


def extract_triage_data(output_dir: str) -> Dict[str, Any]:
    """
    Parses and summarizes forensic artifacts extracted from the sandbox.
    Supports both Velociraptor JSON/CSV outputs and native fallback triage artifacts.
    """
    out_path = Path(output_dir)
    artifacts_zip = out_path / "artifacts.zip"
    
    spawned_processes: List[Dict[str, Any]] = []
    dropped_files: List[Dict[str, Any]] = []
    persistence_entries: List[str] = []
    network_indicators: List[str] = []
    static_indicators: Dict[str, Any] = {}
    
    # 1. Inspect extracted native directory if present
    native_dir = out_path / "native"
    if native_dir.exists():
        procs_file = native_dir / "processes.txt"
        if procs_file.exists():
            spawned_processes.extend(parse_native_processes(procs_file.read_text(encoding="utf-8", errors="ignore")))
            
        drops_file = native_dir / "dropped_files.txt"
        if drops_file.exists():
            dropped_files.extend(parse_native_dropped_files(drops_file.read_text(encoding="utf-8", errors="ignore")))
            
        cron_file = native_dir / "crontabs.txt"
        if cron_file.exists():
            persistence_entries.extend(parse_native_crontabs(cron_file.read_text(encoding="utf-8", errors="ignore")))
            
        net_file = native_dir / "netstat.txt"
        if net_file.exists():
            for line in net_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.strip() and not line.startswith("Active") and not line.startswith("Proto"):
                    network_indicators.append(line.strip())

        static_file = native_dir / "static_indicators.json"
        static_indicators = {}
        if static_file.exists():
            try:
                static_indicators = json.loads(static_file.read_text(encoding="utf-8"))
                ind = static_indicators.get("indicators", {})
                for ip in ind.get("ips", []):
                    if ip not in network_indicators:
                        network_indicators.append(ip)
                for url in ind.get("urls", []):
                    if url not in network_indicators:
                        network_indicators.append(url)
            except Exception as se:
                logger.debug(f"Could not parse static_indicators.json: {se}")

    # 2. Inspect ZIP archive if generated by Velociraptor
    if artifacts_zip.exists():
        try:
            with zipfile.ZipFile(artifacts_zip, "r") as z:
                for filename in z.namelist():
                    # Parse Velociraptor JSON dumps
                    if filename.endswith(".json"):
                        with z.open(filename) as jf:
                            try:
                                data = json.load(jf)
                                if isinstance(data, list):
                                    if "Processes" in filename:
                                        for row in data:
                                            cmd = row.get("CommandLine", "") or row.get("Name", "")
                                            if not any(b in cmd for b in BASELINE_PROCESS_NAMES):
                                                spawned_processes.append({
                                                    "pid": row.get("Pid"),
                                                    "ppid": row.get("Ppid"),
                                                    "command": cmd,
                                                    "username": row.get("Username", "root")
                                                })
                                    elif "Crontab" in filename or "Systemd" in filename:
                                        for row in data:
                                            persistence_entries.append(str(row))
                                    elif "FileFinder" in filename:
                                        for row in data:
                                            dropped_files.append({
                                                "path": row.get("FullPath", ""),
                                                "size": row.get("Size", ""),
                                                "hash": row.get("Hash", {}).get("SHA256", "")
                                            })
                            except Exception as je:
                                logger.debug(f"Could not parse JSON artifact {filename}: {je}")
        except Exception as ze:
            logger.warning(f"Failed to read artifacts.zip: {ze}")

    # 3. Read run summary
    summary_file = out_path / "run_summary.json"
    run_summary = {}
    if summary_file.exists():
        try:
            run_summary = json.loads(summary_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # 4. Decompose raw dropped payloads
    dropped_payloads = analyze_dropped_payloads(out_path)

    return {
        "execution_summary": run_summary,
        "spawned_processes": spawned_processes,
        "dropped_files": dropped_files,
        "dropped_payloads": dropped_payloads,
        "persistence_hooks": persistence_entries,
        "network_indicators": network_indicators,
        "static_indicators": static_indicators,
        "raw_artifacts_available": artifacts_zip.exists()
    }
