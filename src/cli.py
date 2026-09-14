import argparse
import sys
import time
from pathlib import Path

from src.quarantine import quarantine_sample
from src.runner import run_detonation
from src.triage import extract_triage_data
from src.ai_synthesis import synthesize_threat_report
from src.report_generator import generate_threat_report
from src.config import REPORTS_DIR, CLIENT_DAILY_QUOTA
from src.malwarebazaar import (
    get_sample_info,
    download_sample_binary,
    MalwareBazaarUnavailableError,
    SampleNotFoundError,
    UnsupportedArchitectureError
)
from src.rate_limiter import check_client_quota, consume_client_quota


def cmd_submit(args):
    target_path = Path(args.file)
    if not target_path.exists():
        print(f"[!] Error: File '{target_path}' does not exist.")
        sys.exit(1)

    print(f"[*] Reading sample '{target_path.name}'...")
    content = target_path.read_bytes()

    print("[*] Quarantining sample and calculating cryptographic hashes...")
    sample_meta = quarantine_sample(content, target_path.name)
    print(f"    - SHA-256: {sample_meta['sha256']}")
    print(f"    - File Type: {sample_meta['file_type']}")
    print(f"    - Size: {sample_meta['size_bytes']} bytes")
    print(f"    - Quarantine Location: {sample_meta['quarantine_path']}")

    _execute_detonation_flow(sample_meta, args.timeout, args.mock)


def cmd_submit_hash(args):
    sha256 = args.sha256.strip().lower()
    
    # 1. Check Report Cache
    cached_report = REPORTS_DIR / f"{sha256}.md"
    if cached_report.exists() and not args.force:
        print(f"[+] Instant Cache Hit! Threat Analysis Report already exists for SHA256: {sha256}")
        print(f"    Report File: {cached_report}")
        return

    # 2. Check local quota
    allowed, used, remaining = check_client_quota("cli:localhost")
    if not allowed and not args.force:
        print(f"[!] Daily quota exceeded ({used}/{CLIENT_DAILY_QUOTA} detonations used today). Use --force to override in CLI.")
        sys.exit(1)

    # 3. Pre-flight check on MalwareBazaar
    print(f"[*] Querying MalwareBazaar for SHA-256: {sha256}...")
    try:
        sample_info = get_sample_info(sha256)
    except (SampleNotFoundError, UnsupportedArchitectureError, MalwareBazaarUnavailableError, ValueError) as err:
        print(f"[!] {err}")
        sys.exit(1)

    print(f"    - Filename: {sample_info['filename']}")
    print(f"    - Type: {sample_info['file_type']}")
    print(f"    - Signature: {sample_info['signature']}")
    print(f"    - Tags: {', '.join(sample_info['tags'])}")

    # 4. Download and Decrypt Sample
    print("[*] Downloading and decrypting sample from MalwareBazaar...")
    try:
        raw_binary = download_sample_binary(sha256)
    except MalwareBazaarUnavailableError as mbue:
        print(f"[!] {mbue}")
        sys.exit(1)

    # 5. Quarantine
    sample_meta = quarantine_sample(raw_binary, sample_info["filename"])
    print(f"[+] Sample stored in Quarantine Store: {sample_meta['quarantine_path']}")

    # 6. Detonate
    _execute_detonation_flow(sample_meta, args.timeout, args.mock)
    consume_client_quota("cli:localhost")


def _execute_detonation_flow(sample_meta, timeout, mock):
    print(f"[*] Starting Detonation Run (Timeout: {timeout}s)...")
    t0 = time.time()
    detonation_res = run_detonation(
        sample_path=sample_meta["quarantine_path"],
        sha256=sample_meta["sha256"],
        timeout_seconds=timeout,
        mock_run=mock,
        raw_bytes=sample_meta.get("raw_bytes")
    )
    print(f"    - Status: {detonation_res['status']} ({detonation_res.get('execution_mode', 'standard')}) in {time.time() - t0:.1f}s")

    print("[*] Extracting forensic triage artifacts...")
    triage_data = extract_triage_data(detonation_res["output_dir"])
    print(f"    - Spawned Processes: {len(triage_data.get('spawned_processes', []))}")
    print(f"    - Dropped Files: {len(triage_data.get('dropped_files', []))}")
    print(f"    - Discovered Network Indicators: {len(triage_data.get('network_indicators', []))}")

    print("[*] Synthesizing Threat Intelligence via Gemini...")
    synthesis = synthesize_threat_report(sample_meta, triage_data)
    print(f"    - Classification: {synthesis.threat_classification}")
    print(f"    - Family: {synthesis.malware_family}")
    print(f"    - Severity Score: {synthesis.threat_severity_score}/10")
    print(f"    - MITRE Techniques: {len(synthesis.mitre_attack_techniques)}")

    print("[*] Compiling defanged Threat Analysis Report...")
    report_md = generate_threat_report(sample_meta, triage_data, synthesis)
    report_file = REPORTS_DIR / f"{sample_meta['sha256']}.md"
    report_file.write_text(report_md, encoding="utf-8")
    print(f"[+] Report generated successfully at: {report_file}")


def cmd_quota(args):
    allowed, used, remaining = check_client_quota("cli:localhost")
    print("[*] Daily Detonation Quota Status (CLI):")
    print(f"    - Used Today: {used} / {CLIENT_DAILY_QUOTA}")
    print(f"    - Remaining Today: {remaining}")


def cmd_list(args):
    reports = list(REPORTS_DIR.glob("*.md"))
    if not reports:
        print("[*] No threat reports found in reports/ directory.")
        return
    print(f"[*] Found {len(reports)} generated Threat Analysis Report(s):\n")
    for r in reports:
        print(f"  - {r.stem} ({r.stat().st_size} bytes) -> {r}")


def cmd_show(args):
    report_file = REPORTS_DIR / f"{args.sha256}.md"
    if not report_file.exists():
        print(f"[!] Error: No report found for SHA256 '{args.sha256}'.")
        sys.exit(1)
    print(report_file.read_text(encoding="utf-8"))


def cmd_serve(args):
    import uvicorn
    print(f"[*] Starting Detonation API server on http://{args.host}:{args.port}...")
    print(f"[*] Swagger UI available at http://{args.host}:{args.port}/docs")
    uvicorn.run("src.api:app", host=args.host, port=args.port, reload=args.reload)


def main():
    parser = argparse.ArgumentParser(description="Threat Research Pipeline CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # submit-hash
    p_hash = subparsers.add_parser("submit-hash", help="Acquire sample by SHA-256 from MalwareBazaar and detonate")
    p_hash.add_argument("sha256", help="SHA-256 hash of the Linux malware sample")
    p_hash.add_argument("--timeout", type=int, default=90, help="Detonation timeout in seconds (default: 90)")
    p_hash.add_argument("--mock", action="store_true", help="Force mock detonation without running Docker")
    p_hash.add_argument("--force", action="store_true", help="Bypass cache and quota checks")
    p_hash.set_defaults(func=cmd_submit_hash)

    # submit file
    p_submit = subparsers.add_parser("submit", help="Submit and detonate a local sample binary")
    p_submit.add_argument("file", help="Path to sample file to analyze")
    p_submit.add_argument("--timeout", type=int, default=90, help="Detonation timeout in seconds (default: 90)")
    p_submit.add_argument("--mock", action="store_true", help="Force mock detonation without running Docker")
    p_submit.set_defaults(func=cmd_submit)

    # quota
    p_quota = subparsers.add_parser("quota", help="Inspect remaining daily detonation quota")
    p_quota.set_defaults(func=cmd_quota)

    # list
    p_list = subparsers.add_parser("list", help="List all generated threat reports")
    p_list.set_defaults(func=cmd_list)

    # show
    p_show = subparsers.add_parser("show", help="Show threat report by SHA-256")
    p_show.add_argument("sha256", help="SHA-256 of the sample")
    p_show.set_defaults(func=cmd_show)

    # serve
    p_serve = subparsers.add_parser("serve", help="Launch FastAPI web server")
    p_serve.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    p_serve.add_argument("--port", type=int, default=8000, help="Bind port (default: 8000)")
    p_serve.add_argument("--reload", action="store_true", help="Enable live auto-reload")
    p_serve.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
