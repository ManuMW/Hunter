import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Any

from src.config import REPORTS_DIR
from src.ai_synthesis import ThreatAnalysisSynthesis


def defang_ioc(text: str) -> str:
    """
    Defangs potentially malicious indicators (URLs, IPs, domains)
    to prevent accidental clicking and security crawler abuse flags.
    """
    if not text:
        return ""
    # Defang protocols
    text = re.sub(r"https://", "hxxps://", text, flags=re.IGNORECASE)
    text = re.sub(r"http://", "hxxp://", text, flags=re.IGNORECASE)
    text = re.sub(r"ftp://", "fxp://", text, flags=re.IGNORECASE)
    
    # Defang IPv4 addresses
    text = re.sub(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b", r"\1[.]\2[.]\3[.]\4", text)
    
    # Defang domain extensions (e.g. .com -> [.]com)
    text = re.sub(r"(\w+)\.(com|org|net|ru|cn|xyz|top|info|biz|io|cc|pw)\b", r"\1[.]\2", text, flags=re.IGNORECASE)
    return text


def generate_threat_report(
    sample_meta: Dict[str, Any],
    triage_data: Dict[str, Any],
    synthesis: ThreatAnalysisSynthesis
) -> str:
    """
    Constructs a comprehensive, defanged Markdown Threat Analysis Report
    ready for publishing on GitHub Pages or local inspection.
    """
    sha256 = sample_meta.get("sha256", "unknown")
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    
    # Severity badge color
    score = synthesis.threat_severity_score
    badge_color = "red" if score >= 8 else "orange" if score >= 5 else "green"
    
    report_lines = [
        "---",
        f"title: Threat Analysis Report - {sample_meta.get('filename')}",
        f"date: {now_iso}",
        f"sha256: {sha256}",
        f"severity_score: {score}",
        f"malware_family: \"{synthesis.malware_family}\"",
        f"classification: \"{synthesis.threat_classification}\"",
        "tags:",
        f"  - {synthesis.threat_classification}",
        f"  - Severity_{score}",
        "---",
        "",
        f"# Threat Analysis Report: `{sample_meta.get('filename')}`",
        "",
        f"> **Analysis Timestamp**: {now_iso}  ",
        f"> **Threat Classification**: `{synthesis.threat_classification}`  ",
        f"> **Severity Score**: **{score}/10**  ",
        f"> **Suspected Family**: `{synthesis.malware_family}`  ",
        f"> **Confidence**: `{int(synthesis.confidence_score * 100)}%`",
        "",
        "## 1. Executive Summary",
        "",
        synthesis.executive_summary,
        "",
        "## 2. Sample File Details",
        "",
        "| Attribute | Value |",
        "| :--- | :--- |",
        f"| **Original Filename** | `{sample_meta.get('filename')}` |",
        f"| **File Type** | `{sample_meta.get('file_type')}` |",
        f"| **File Size** | `{sample_meta.get('size_bytes')} bytes` |",
        f"| **SHA-256** | `{sha256}` |",
        f"| **SHA-1** | `{sample_meta.get('sha1')}` |",
        f"| **MD5** | `{sample_meta.get('md5')}` |",
        "",
        "## 3. MITRE ATT&CK Mapping",
        "",
        "| Technique ID | Technique Name | Tactic | Observed Forensic Evidence |",
        "| :--- | :--- | :--- | :--- |"
    ]

    if synthesis.mitre_attack_techniques:
        for m in synthesis.mitre_attack_techniques:
            report_lines.append(
                f"| [`{m.technique_id}`](https://attack.mitre.org/techniques/{m.technique_id.replace('.', '/')}) | {m.technique_name} | `{m.tactic}` | {defang_ioc(m.evidence)} |"
            )
    else:
        report_lines.append("| None | No standard techniques identified | N/A | Air-gapped run exhibited no observable triggers |")

    report_lines.extend([
        "",
        "## 4. Observed Dynamic Behaviors",
        "",
        "| Category | Description | Evidence |",
        "| :--- | :--- | :--- |"
    ])

    if synthesis.observed_behaviors:
        for b in synthesis.observed_behaviors:
            report_lines.append(f"| `{b.category}` | {b.description} | `{defang_ioc(b.evidence)}` |")
    else:
        report_lines.append("| General | Sample ran for 90 seconds without notable events | None |")

    report_lines.extend([
        "",
        "## 5. Indicators of Compromise (IoCs)",
        "",
        "| Type | Defanged Value | Description |",
        "| :--- | :--- | :--- |"
    ])

    if synthesis.indicators_of_compromise:
        for ioc in synthesis.indicators_of_compromise:
            report_lines.append(f"| `{ioc.type}` | `{defang_ioc(ioc.value)}` | {ioc.description} |")
    else:
        report_lines.append(f"| `sha256` | `{sha256}` | Primary Sample SHA-256 |")

    # Add forensic dump section
    report_lines.extend([
        "",
        "## 6. Detailed Sandbox Forensic Triage",
        "",
        "### Spawned Process Tree",
        "```text"
    ])
    procs = triage_data.get("spawned_processes", [])
    if procs:
        for p in procs:
            report_lines.append(f"PID {p.get('pid', '?')} (User: {p.get('user', p.get('username', 'root'))}): {defang_ioc(p.get('command', ''))}")
    else:
        report_lines.append("No unexpected child processes detected.")
    report_lines.append("```")

    report_lines.extend([
        "",
        "### Staged & Dropped Files",
        "```text"
    ])
    drops = triage_data.get("dropped_files", [])
    if drops:
        for d in drops:
            report_lines.append(f"{d.get('permissions', '')} {d.get('size', '')} {defang_ioc(d.get('path', ''))}")
    else:
        report_lines.append("No modified files staged in temporary directories.")
    report_lines.append("```")

    if triage_data.get("persistence_hooks"):
        report_lines.extend([
            "",
            "### Persistence Hooks (Cron/Systemd)",
            "```text"
        ])
        for hook in triage_data["persistence_hooks"]:
            report_lines.append(defang_ioc(hook))
        report_lines.append("```")

    # YARA Rule
    report_lines.extend([
        "",
        "## 7. YARA Detection Rule",
        "",
        "```yara",
        synthesis.yara_rule_candidate.strip(),
        "```",
        "",
        "---",
        "*Report automatically generated by Threat Research Pipeline.*"
    ])

    report_content = "\n".join(report_lines)
    
    # Save report to reports/<sha256>.md
    report_file = REPORTS_DIR / f"{sha256}.md"
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(report_content)
        
    return report_content
