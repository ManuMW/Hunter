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
        f"| **MD5** | `{sample_meta.get('md5')}` |"
    ]

    # Include MalwareBazaar signature and tags if available
    if sample_meta.get("signature") and sample_meta.get("signature") != "Unclassified":
        report_lines.append(f"| **Vendor Signature** | `{sample_meta.get('signature')}` |")
    if sample_meta.get("tags"):
        report_lines.append(f"| **Threat Tags** | `{', '.join(sample_meta.get('tags'))}` |")

    # Static ELF decomposition details
    static_data = triage_data.get("static_indicators", {})
    elf_info = static_data.get("elf_info", {})
    if elf_info.get("is_elf"):
        arch = elf_info.get("architecture") or elf_info.get("machine") or "Unknown"
        report_lines.append(f"| **ELF Architecture** | `{arch}` |")
        report_lines.append(f"| **ELF Class / Endianness** | `{elf_info.get('class', 'N/A')} / {elf_info.get('endianness', 'N/A')}` |")
        if static_data.get("entropy") is not None:
            report_lines.append(f"| **Shannon Entropy** | `{static_data.get('entropy')}` |")

    # Security Mitigations sub-table
    mitigations = elf_info.get("security_mitigations", {})
    if mitigations:
        report_lines.extend([
            "",
            "### Binary Hardening & Exploit Mitigations",
            "",
            "| Mitigation | Security Status |",
            "| :--- | :--- |",
            f"| **Stack Canary** | `{mitigations.get('canary', 'Not Checked')}` |",
            f"| **NX / DEP (No-Execute)** | `{mitigations.get('nx', 'Not Checked')}` |",
            f"| **Position Independent Executable (PIE)** | `{mitigations.get('pie', 'Not Checked')}` |",
            f"| **Relocation Read-Only (RelRO)** | `{mitigations.get('relro', 'Not Checked')}` |",
            f"| **Symbol Table** | `{mitigations.get('stripped', 'Not Checked')}` |"
        ])

    # XOR Deobfuscation Findings
    xor_decomp = static_data.get("xor_deobfuscation", {})
    if xor_decomp.get("is_xor_obfuscated"):
        keys_list = [k.get("key_hex", "") for k in xor_decomp.get("detected_keys", [])]
        report_lines.extend([
            "",
            "### Cryptographic Obfuscation Triage",
            "",
            f"> [!IMPORTANT]",
            f"> Static deobfuscation detected single-byte XOR string encoding utilizing key(s): **{', '.join(keys_list)}**."
        ])

    report_lines.extend([
        "",
        "## 3. MITRE ATT&CK Mapping",
        "",
        "| Technique ID | Technique Name | Tactic | Observed Forensic Evidence |",
        "| :--- | :--- | :--- | :--- |"
    ])

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

    # Dropped Payloads Decomposition Section (HUN-27: Section 6 always present)
    report_lines.extend([
        "",
        "## 6. Dropped Payloads & Multi-Stage Attack Decomposition",
        ""
    ])
    if synthesis.dropped_payload_analyses:
        report_lines.extend([
            "> [!NOTE]",
            "> All executable sub-payloads staged during execution have been quarantined on the Detonation Host and are available for standalone detonation.",
            "",
            "| Dropped File | Operational Role | File Type | SHA-256 | Quarantine Status |",
            "| :--- | :--- | :--- | :--- | :--- |"
        ])
        for p in synthesis.dropped_payload_analyses:
            report_lines.append(
                f"| `{p.filename}` | `{p.role}` | `{p.file_type}` | `{p.sha256}` | `Quarantined (Detonatable)` |"
            )
        
        report_lines.extend(["", "### Sub-Payload Analysis Deep-Dive", ""])
        for p in synthesis.dropped_payload_analyses:
            report_lines.extend([
                f"#### Target: `{p.filename}` ({p.role})",
                f"- **SHA-256**: `{p.sha256}`",
                f"- **File Type**: `{p.file_type}`",
                f"- **Behavioral Role**: {p.analysis}",
            ])
            if p.embedded_indicators:
                report_lines.append(f"- **Extracted Indicators / Configs**: {', '.join(f'`{defang_ioc(i)}`' for i in p.embedded_indicators)}")
            report_lines.append("")
    else:
        report_lines.extend([
            "No secondary dropped payloads or staged execution stages were identified during binary decomposition.",
            ""
        ])

    # Add forensic dump section
    report_lines.extend([
        "",
        "## 7. Detailed Sandbox Forensic Triage",
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
        "## 8. YARA Detection Rule",
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
