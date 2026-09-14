"""
Sync Threat Reports from GCP Cloud Detonation Host
Fetches new or specific reports from the Hunter Detonation API,
saves reports/<sha256>.md, and updates data/reports.js & web/data/reports.js.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
import httpx

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
DATA_REPORTS_JS = REPO_ROOT / "data" / "reports.js"
WEB_DATA_REPORTS_JS = REPO_ROOT / "web" / "data" / "reports.js"


def fetch_report_json(api_url: str, sha256: str) -> Optional[Dict[str, Any]]:
    url = f"{api_url.rstrip('/')}/api/reports/{sha256}?format=json"
    try:
        resp = httpx.get(url, timeout=30.0)
        if resp.status_code == 200:
            return resp.json()
        print(f"[!] Warning: HTTP {resp.status_code} fetching JSON for {sha256}")
    except Exception as e:
        print(f"[!] Error fetching report JSON for {sha256}: {e}")
    return None


def fetch_report_markdown(api_url: str, sha256: str) -> Optional[str]:
    url = f"{api_url.rstrip('/')}/api/reports/{sha256}?format=markdown"
    try:
        resp = httpx.get(url, timeout=30.0)
        if resp.status_code == 200:
            return resp.text
        print(f"[!] Warning: HTTP {resp.status_code} fetching Markdown for {sha256}")
    except Exception as e:
        print(f"[!] Error fetching report Markdown for {sha256}: {e}")
    return None


def list_remote_reports(api_url: str) -> List[str]:
    url = f"{api_url.rstrip('/')}/api/reports"
    try:
        resp = httpx.get(url, timeout=30.0)
        if resp.status_code == 200:
            items = resp.json()
            return [item.get("sha256") for item in items if item.get("sha256")]
    except Exception as e:
        print(f"[!] Error listing remote reports: {e}")
    return []


def append_to_catalog(report_dict: Dict[str, Any]) -> bool:
    updated = False
    sha256 = report_dict.get("sha256")
    if not sha256:
        return False

    for file_path in [DATA_REPORTS_JS, WEB_DATA_REPORTS_JS]:
        if not file_path.exists():
            continue
        content = file_path.read_text(encoding="utf-8")
        if sha256 in content:
            continue

        prefix = "const THREAT_REPORTS = [\n"
        idx = content.find(prefix)
        if idx != -1:
            json_str = json.dumps(report_dict, indent=4)
            indented = "\n".join("    " + line for line in json_str.splitlines()) + ",\n"
            new_content = content[:idx + len(prefix)] + indented + content[idx + len(prefix):]
            file_path.write_text(new_content, encoding="utf-8")
            print(f"[+] Added {sha256[:12]} to {file_path.relative_to(REPO_ROOT)}")
            updated = True
    return updated


def process_sha256(api_url: str, sha256: str) -> bool:
    print(f"[*] Processing report for SHA-256: {sha256}...")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # 1. Fetch Markdown
    md_content = fetch_report_markdown(api_url, sha256)
    if md_content:
        md_file = REPORTS_DIR / f"{sha256}.md"
        md_file.write_text(md_content, encoding="utf-8")
        print(f"[+] Saved report markdown: reports/{sha256}.md")
    else:
        print(f"[!] Could not retrieve Markdown for {sha256}")
        return False

    # 2. Fetch JSON and update catalog
    report_json = fetch_report_json(api_url, sha256)
    if report_json:
        append_to_catalog(report_json)
    else:
        print(f"[!] Could not retrieve JSON for {sha256}")
    return True


def main():
    parser = argparse.ArgumentParser(description="Sync reports from GCP Detonation Host")
    parser.add_argument("--api-url", required=True, help="Base URL of GCP Detonation API")
    parser.add_argument("--sha256", help="Specific SHA-256 hash to fetch (optional)")
    args = parser.parse_args()

    api_url = args.api_url.rstrip("/")

    if args.sha256:
        success = process_sha256(api_url, args.sha256.strip().lower())
        sys.exit(0 if success else 1)

    print(f"[*] Querying available reports from {api_url}...")
    remote_hashes = list_remote_reports(api_url)
    if not remote_hashes:
        print("[*] No reports found or failed to connect.")
        sys.exit(0)

    print(f"[*] Found {len(remote_hashes)} remote report(s). Checking for missing local reports...")
    synced_count = 0
    for h in remote_hashes:
        local_md = REPORTS_DIR / f"{h}.md"
        if not local_md.exists():
            if process_sha256(api_url, h):
                synced_count += 1

    print(f"[+] Sync finished. {synced_count} new report(s) synced.")


if __name__ == "__main__":
    main()
