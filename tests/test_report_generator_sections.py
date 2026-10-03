import re
from src.ai_synthesis import ThreatAnalysisSynthesis
from src.report_generator import generate_threat_report


def test_section_numbering_without_dropped_payloads_hun27(tmp_path, monkeypatch):
    monkeypatch.setattr("src.report_generator.REPORTS_DIR", tmp_path)
    sample_meta = {
        "filename": "standalone_bot.elf",
        "sha256": "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        "file_type": "Linux ELF",
        "size_bytes": 32768,
        "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "md5": "d41d8cd98f00b204e9800998ecf8427e",
        "signature": "Mirai",
        "tags": ["Mirai", "botnet"]
    }
    triage_data = {
        "spawned_processes": [],
        "dropped_files": [],
        "persistence_hooks": [],
        "static_indicators": {
            "elf_info": {
                "is_elf": True,
                "architecture": "ARM (32-bit)",
                "class": "32-bit",
                "endianness": "Little Endian",
                "security_mitigations": {
                    "canary": "Not Detected",
                    "nx": "Enabled",
                    "pie": "Disabled (Fixed Address)",
                    "relro": "No RelRO",
                    "stripped": "Stripped"
                }
            },
            "entropy": 5.95,
            "xor_deobfuscation": {
                "is_xor_obfuscated": True,
                "detected_keys": [{"key_hex": "0x22"}]
            }
        }
    }
    synthesis = ThreatAnalysisSynthesis(
        malware_family="Mirai Botnet",
        threat_severity_score=8,
        threat_classification="Botnet",
        executive_summary="Sample analysis completed.",
        mitre_attack_techniques=[],
        observed_behaviors=[],
        indicators_of_compromise=[],
        dropped_payload_analyses=[],  # EMPTY: triggers HUN-27 test
        yara_rule_candidate="rule Test { condition: true }",
        confidence_score=0.9
    )

    report_md = generate_threat_report(sample_meta, triage_data, synthesis)

    # Check that all sections 1 to 8 exist in strict order
    sections = re.findall(r"^## (\d)\. (.+)$", report_md, re.MULTILINE)
    section_numbers = [int(num) for num, _ in sections]

    # Must contain 1, 2, 3, 4, 5, 6, 7, 8 without gaps
    assert section_numbers == [1, 2, 3, 4, 5, 6, 7, 8]

    # Section 6 must state clean empty message
    assert "## 6. Dropped Payloads & Multi-Stage Attack Decomposition" in report_md
    assert "No secondary dropped payloads or staged execution stages were identified" in report_md

    # Binary hardening table must be rendered
    assert "Binary Hardening & Exploit Mitigations" in report_md
    assert "Cryptographic Obfuscation Triage" in report_md
