"""
Hunter Security Labs - Administrative Threat Report Management Engine
Provides administrative commands for catalog maintenance, pruning deleted
reports, deleting specific samples, restoring reports from git history,
and synchronizing changes to GitHub Pages.
Adheres to HUN-22.
"""

import argparse
import json
import logging
import re
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO_ROOT / "reports"
DATA_DIR = REPO_ROOT / "data"
CATALOG_PATH = DATA_DIR / "reports.js"
DB_PATH = DATA_DIR / "hunter.db"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("manage_reports")


def load_catalog(catalog_path: Path = CATALOG_PATH) -> List[Dict[str, Any]]:
    """Loads catalog array from data/reports.js handling JSON and JS object formats."""
    if not catalog_path.exists():
        return []

    content = catalog_path.read_text(encoding="utf-8")
    start_idx = content.find("[")
    end_idx = content.rfind("]")
    if start_idx == -1 or end_idx == -1:
        return []

    raw = content[start_idx:end_idx + 1]

    # 1. Attempt standard JSON parsing
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    # 2. Attempt Node.js evaluation if available
    try:
        script = (
            f"const fs = require('fs');\n"
            f"eval(fs.readFileSync({json.dumps(str(catalog_path))}, 'utf8') + '; global.THREAT_REPORTS = THREAT_REPORTS;');\n"
            f"console.log(JSON.stringify(global.THREAT_REPORTS));"
        )
        res = subprocess.run(["node", "-e", script], capture_output=True, text=True, check=True)
        return json.loads(res.stdout)
    except Exception as e:
        logger.debug(f"Node execution failed: {e}")

    # 3. Fallback: rudimentary JS object to JSON conversion
    try:
        # Quote unquoted keys (e.g., id: -> "id":)
        normalized = re.sub(r'(\s*)([a-zA-Z0-9_]+)\s*:', r'\1"\2":', raw)
        # Convert template strings (`...`) into standard escaped JSON strings
        def _replace_template(match):
            inner = match.group(1).replace('"', '\\"').replace('\n', '\\n')
            return f'"{inner}"'
        normalized = re.sub(r'`([^`]*)`', _replace_template, normalized)
        # Remove trailing commas before closing braces/brackets
        normalized = re.sub(r',\s*([}\]])', r'\1', normalized)
        return json.loads(normalized)
    except Exception as e:
        logger.error(f"Failed to parse {catalog_path}: {e}")
        return []


def _format_path(p: Path) -> str:
    try:
        return str(p.relative_to(REPO_ROOT))
    except ValueError:
        return str(p)


def save_catalog(reports: List[Dict[str, Any]], catalog_path: Path = CATALOG_PATH):
    """Saves reports catalog as standardized JavaScript defining THREAT_REPORTS."""
    catalog_path.parent.mkdir(parents=True, exist_ok=True)
    header = (
        "/**\n"
        " * Hunter Security Labs - Cataloged Threat Intelligence Reports\n"
        " * Generated from live detonation runs in Hunter\n"
        " */\n\n"
        "const THREAT_REPORTS = "
    )
    json_str = json.dumps(reports, indent=4)
    content = f"{header}{json_str};\n"
    catalog_path.write_text(content, encoding="utf-8")
    logger.info(f"[+] Saved {len(reports)} report(s) to {_format_path(catalog_path)}")


def parse_frontmatter(md_path: Path) -> Dict[str, Any]:
    """Extracts frontmatter and summary details from a report markdown file."""
    if not md_path.exists():
        return {}
    content = md_path.read_text(encoding="utf-8")
    meta = {}

    title_match = re.search(r"^title:\s*(.+)$", content, re.MULTILINE)
    if title_match:
        meta["title"] = title_match.group(1).strip().strip('"\'')

    family_match = re.search(r"^malware_family:\s*(.+)$", content, re.MULTILINE)
    if family_match:
        meta["family"] = family_match.group(1).strip().strip('"\'')

    classification_match = re.search(r"^classification:\s*(.+)$", content, re.MULTILINE)
    if classification_match:
        meta["category"] = classification_match.group(1).strip().strip('"\'').upper()

    score_match = re.search(r"^severity_score:\s*(\d+)", content, re.MULTILINE)
    if score_match:
        score = int(score_match.group(1))
        meta["severity_score"] = score
        meta["severityScore"] = f"{score}/10"
        meta["severity"] = "CRITICAL" if score >= 8 else "HIGH" if score >= 6 else "MEDIUM"

    date_match = re.search(r"^date:\s*(.+)$", content, re.MULTILINE)
    if date_match:
        meta["date"] = date_match.group(1).strip().strip('"\'')

    author_match = re.search(r"^author:\s*(.+)$", content, re.MULTILINE)
    if author_match:
        meta["author"] = author_match.group(1).strip().strip('"\'')

    # Executive Summary extraction
    summary_match = re.search(r"## 1\. Executive Summary\s*\n\s*(.+?)(?=\n## |\Z)", content, re.DOTALL)
    if summary_match:
        meta["summary"] = summary_match.group(1).strip()

    sha_match = re.search(r"^sha256:\s*([a-f0-9]{64})", content, re.MULTILINE | re.IGNORECASE)
    if not sha_match:
        sha_match = re.search(r"Primary SHA256:\s*`([a-f0-9]{64})`", content, re.IGNORECASE)
    if sha_match:
        meta["sha256"] = sha_match.group(1).lower()
    else:
        meta["sha256"] = md_path.stem.lower()

    meta["id"] = meta["sha256"]
    return meta


def list_reports(reports_dir: Path = REPORTS_DIR, catalog_path: Path = CATALOG_PATH) -> List[Dict[str, Any]]:
    """Lists all cataloged reports along with their disk presence status."""
    reports = load_catalog(catalog_path)
    status_list = []

    print("\n" + "=" * 95)
    print(f"{'SHA-256 (Prefix)':<18} | {'Family':<16} | {'Category':<12} | {'Severity':<10} | {'Status':<12} | {'Date':<10}")
    print("=" * 95)

    if not reports:
        print("No threat reports found in catalog.")
        print("=" * 95 + "\n")
        return []

    for r in reports:
        sha = r.get("sha256") or r.get("id") or "UNKNOWN"
        md_file = reports_dir / f"{sha}.md"
        exists = md_file.exists()
        status_str = "PRESENT" if exists else "DELETED"
        family = (r.get("family") or "Unknown")[:15]
        category = (r.get("category") or "UNKNOWN")[:11]
        severity = (r.get("severity") or "UNKNOWN")[:9]
        date = (r.get("date") or "Unknown")[:10]

        print(f"{sha[:16]:<18} | {family:<16} | {category:<12} | {severity:<10} | {status_str:<12} | {date:<10}")

        status_list.append({
            "sha256": sha,
            "family": family,
            "category": category,
            "severity": severity,
            "markdown_present": exists,
            "report_data": r
        })

    print("=" * 95)
    total = len(reports)
    present_cnt = sum(1 for s in status_list if s["markdown_present"])
    missing_cnt = total - present_cnt
    print(f"Total: {total} | Markdown Present: {present_cnt} | Missing/Deleted: {missing_cnt}\n")
    return status_list


def delete_report(
    sha256: str,
    reports_dir: Path = REPORTS_DIR,
    catalog_path: Path = CATALOG_PATH,
    db_path: Path = DB_PATH
) -> bool:
    """
    Completely removes a report by SHA-256 from:
    1. reports/<sha256>.md
    2. data/reports.js
    3. SQLite data/hunter.db
    """
    clean_sha = sha256.lower().strip()
    reports = load_catalog(catalog_path)
    initial_len = len(reports)

    # 1. Remove from catalog
    updated = [r for r in reports if (r.get("sha256") or r.get("id") or "").lower() != clean_sha]
    removed_from_catalog = (len(updated) < initial_len)
    if removed_from_catalog:
        save_catalog(updated, catalog_path)
        print(f"[+] Removed {clean_sha[:16]}... from {catalog_path.name}")
    else:
        print(f"[*] Hash {clean_sha[:16]}... was not in catalog.")

    # 2. Remove markdown file
    md_file = reports_dir / f"{clean_sha}.md"
    file_deleted = False
    if md_file.exists():
        md_file.unlink()
        file_deleted = True
        print(f"[+] Deleted report markdown file: {_format_path(md_file)}")
    else:
        print(f"[*] No markdown file existed at reports/{clean_sha}.md")

    # 3. Remove from SQLite DB if present
    db_deleted = 0
    if db_path.exists():
        try:
            with sqlite3.connect(str(db_path)) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM detonation_tasks WHERE sha256 = ?", (clean_sha,))
                conn.commit()
                db_deleted = cursor.rowcount
                if db_deleted > 0:
                    print(f"[+] Removed {db_deleted} record(s) from SQLite tasks database.")
        except Exception as e:
            logger.warning(f"Failed to delete {clean_sha} from SQLite DB: {e}")

    success = removed_from_catalog or file_deleted or (db_deleted > 0)
    if success:
        print(f"[+] Successfully purged threat report for {clean_sha}")
    else:
        print(f"[!] No artifacts found for {clean_sha}")
    return success


def prune_catalog(
    reports_dir: Path = REPORTS_DIR,
    catalog_path: Path = CATALOG_PATH,
    db_path: Path = DB_PATH
) -> List[str]:
    """
    Prunes any entries from data/reports.js that do not have corresponding
    markdown files in reports/.
    """
    reports = load_catalog(catalog_path)
    pruned_hashes = []
    kept_reports = []

    for r in reports:
        sha = (r.get("sha256") or r.get("id") or "").lower().strip()
        md_file = reports_dir / f"{sha}.md"
        if md_file.exists():
            kept_reports.append(r)
        else:
            pruned_hashes.append(sha)

    if pruned_hashes:
        save_catalog(kept_reports, catalog_path)
        print(f"[+] Pruned {len(pruned_hashes)} missing report(s) from catalog:")
        for h in pruned_hashes:
            print(f"    - {h}")

        # Also prune SQLite records for these deleted files if DB exists
        if db_path.exists():
            try:
                with sqlite3.connect(str(db_path)) as conn:
                    cursor = conn.cursor()
                    cursor.executemany(
                        "DELETE FROM detonation_tasks WHERE sha256 = ?",
                        [(h,) for h in pruned_hashes]
                    )
                    conn.commit()
                    if cursor.rowcount > 0:
                        print(f"[+] Cleared {cursor.rowcount} task entries from SQLite DB.")
            except Exception as e:
                logger.warning(f"Failed to prune SQLite tasks: {e}")
    else:
        print("[*] Catalog is already synchronized. No missing reports to prune.")

    return pruned_hashes


def restore_report(
    sha256: str,
    commit: str = "0ac3048",
    reports_dir: Path = REPORTS_DIR,
    catalog_path: Path = CATALOG_PATH
) -> bool:
    """Restores a deleted report markdown file from git history and updates catalog."""
    clean_sha = sha256.lower().strip()
    target_rel = f"reports/{clean_sha}.md"

    # 1. Checkout markdown file from commit
    cmd = ["git", "checkout", commit, "--", target_rel]
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=REPO_ROOT)
        print(f"[+] Checked out {target_rel} from commit {commit}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Git checkout failed: {e.stderr}")
        return False

    # 2. Check if we can get catalog entry from that commit as well
    catalog_entry = None
    try:
        show_cmd = ["git", "show", f"{commit}:data/reports.js"]
        show_res = subprocess.run(show_cmd, capture_output=True, text=True, check=True, cwd=REPO_ROOT)
        old_content = show_res.stdout
        # Temporary file to load old catalog safely
        temp_file = REPO_ROOT / "data" / ".temp_reports.js"
        temp_file.write_text(old_content, encoding="utf-8")
        old_catalog = load_catalog(temp_file)
        temp_file.unlink(missing_ok=True)

        catalog_entry = next((r for r in old_catalog if (r.get("sha256") or r.get("id") or "").lower() == clean_sha), None)
    except Exception as e:
        logger.debug(f"Could not retrieve old catalog entry from commit: {e}")

    # Fallback to frontmatter
    if not catalog_entry:
        meta = parse_frontmatter(reports_dir / f"{clean_sha}.md")
        catalog_entry = {
            "id": clean_sha,
            "sha256": clean_sha,
            "title": meta.get("title", f"Threat Analysis Report: {clean_sha[:12]}"),
            "family": meta.get("family", "Unknown"),
            "category": "BENIGN",
            "severity": "MEDIUM",
            "date": meta.get("date", "2026-10-02"),
            "author": meta.get("author", "Hunter Research Team"),
            "readTime": "4 min read",
            "summary": "Restored threat intelligence report.",
            "tags": [meta.get("family", "UNKNOWN").upper()],
            "mitre": [],
            "iocs": [{"type": "sha256", "value": clean_sha, "description": "Primary sample SHA-256"}]
        }

    # 3. Add to catalog if not present
    current_catalog = load_catalog(catalog_path)
    if not any((r.get("sha256") or r.get("id") or "").lower() == clean_sha for r in current_catalog):
        current_catalog.insert(0, catalog_entry)
        save_catalog(current_catalog, catalog_path)
        print(f"[+] Re-indexed {clean_sha[:16]}... in {catalog_path.name}")

    print(f"[+] Successfully restored report for {clean_sha}")
    return True


def rebuild_catalog(reports_dir: Path = REPORTS_DIR, catalog_path: Path = CATALOG_PATH) -> int:
    """
    Rebuilds catalog from existing markdown files.
    Preserves existing metadata if present, updating frontmatter fields, and extracts frontmatter for new files.
    """
    existing_catalog = {
        (r.get("sha256") or r.get("id") or "").lower(): r
        for r in load_catalog(catalog_path)
    }

    rebuilt_list = []
    reports_dir.mkdir(parents=True, exist_ok=True)
    md_files = list(reports_dir.glob("*.md"))

    for md in md_files:
        sha = md.stem.lower()
        meta = parse_frontmatter(md)
        if sha in existing_catalog:
            entry = dict(existing_catalog[sha])
            if "title" in meta:
                entry["title"] = meta["title"]
            if "family" in meta:
                entry["family"] = meta["family"]
            if "category" in meta:
                entry["category"] = meta["category"]
            if "severity" in meta:
                entry["severity"] = meta["severity"]
            if "severityScore" in meta:
                entry["severityScore"] = meta["severityScore"]
            if "summary" in meta:
                entry["summary"] = meta["summary"]
            if "date" in meta:
                entry["date"] = meta["date"]
            rebuilt_list.append(entry)
        else:
            rebuilt_list.append({
                "id": sha,
                "sha256": sha,
                "title": meta.get("title", f"Threat Analysis Report: {sha[:12]}"),
                "family": meta.get("family", "Unknown"),
                "category": meta.get("category", "BENIGN"),
                "severity": meta.get("severity", "MEDIUM"),
                "severityScore": meta.get("severityScore", "5/10"),
                "date": meta.get("date", "2026-10-02"),
                "author": meta.get("author", "Hunter Research Team"),
                "readTime": "4 min read",
                "summary": meta.get("summary", "Rebuilt threat report catalog entry."),
                "tags": [meta.get("family", "UNKNOWN").upper()],
                "mitre": [],
                "iocs": [{"type": "sha256", "value": sha, "description": "Primary SHA-256"}]
            })

    save_catalog(rebuilt_list, catalog_path)
    print(f"[+] Rebuilt catalog with {len(rebuilt_list)} report(s).")
    return len(rebuilt_list)


def sync_git(message: str = "chore(reports): synchronize catalog and prune deleted threat reports [HUN-22]") -> bool:
    """Stages reports/ and data/reports.js, commits, and pushes to origin/main."""
    try:
        subprocess.run(["git", "add", "reports/", "data/reports.js"], cwd=REPO_ROOT, check=True)
        status = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=REPO_ROOT)
        if status.returncode == 0:
            print("[*] No changes staged. Git working tree is already clean.")
            return True

        subprocess.run(["git", "commit", "-m", message], cwd=REPO_ROOT, check=True)
        print(f"[+] Committed changes: {message}")
        subprocess.run(["git", "push", "origin", "main"], cwd=REPO_ROOT, check=True)
        print("[+] Pushed updates to origin/main. GitHub Pages deployment triggered.")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Git sync failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Hunter Security Labs - Threat Report Management CLI (HUN-22)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python -m scripts.manage_reports list
  python -m scripts.manage_reports prune --push
  python -m scripts.manage_reports delete <sha256> --push
  python -m scripts.manage_reports restore <sha256> --commit 0ac3048 --push
  python -m scripts.manage_reports rebuild --push
"""
    )
    subparsers = parser.add_subparsers(dest="command", required=True, help="Administrative command")

    # Command: list
    subparsers.add_parser("list", help="List all cataloged reports and file presence")

    # Command: prune
    prune_parser = subparsers.add_parser("prune", help="Prune missing reports from data/reports.js")
    prune_parser.add_argument("--push", action="store_true", help="Commit and push changes to git")

    # Command: delete
    del_parser = subparsers.add_parser("delete", help="Delete a specific report by SHA-256")
    del_parser.add_argument("sha256", help="SHA-256 hash of the report to delete")
    del_parser.add_argument("--push", action="store_true", help="Commit and push changes to git")

    # Command: restore
    res_parser = subparsers.add_parser("restore", help="Restore a deleted report from git history")
    res_parser.add_argument("sha256", help="SHA-256 hash of the report to restore")
    res_parser.add_argument("--commit", default="0ac3048", help="Git commit hash to restore from (default: 0ac3048)")
    res_parser.add_argument("--push", action="store_true", help="Commit and push changes to git")

    # Command: rebuild
    reb_parser = subparsers.add_parser("rebuild", help="Rebuild catalog strictly from reports/*.md")
    reb_parser.add_argument("--push", action="store_true", help="Commit and push changes to git")

    # Command: sync
    sync_parser = subparsers.add_parser("sync", help="Prune catalog and push to GitHub")
    sync_parser.add_argument("-m", "--message", default="chore(reports): synchronize catalog and prune deleted threat reports [HUN-22]", help="Custom commit message")

    args = parser.parse_args()

    if args.command == "list":
        list_reports()
    elif args.command == "prune":
        pruned = prune_catalog()
        if args.push and pruned:
            sync_git()
    elif args.command == "delete":
        deleted = delete_report(args.sha256)
        if args.push and deleted:
            sync_git(f"chore(reports): delete threat report {args.sha256[:12]} [HUN-22]")
    elif args.command == "restore":
        restored = restore_report(args.sha256, commit=args.commit)
        if args.push and restored:
            sync_git(f"chore(reports): restore threat report {args.sha256[:12]} [HUN-22]")
    elif args.command == "rebuild":
        rebuild_catalog()
        if args.push:
            sync_git("chore(reports): rebuild threat catalog [HUN-22]")
    elif args.command == "sync":
        prune_catalog()
        sync_git(args.message)


if __name__ == "__main__":
    main()
