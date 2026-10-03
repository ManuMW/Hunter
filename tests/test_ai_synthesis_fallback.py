import pytest
from src.ai_synthesis import _deterministic_fallback_synthesis


def test_malwarebazaar_signature_attribution_hun24():
    sample_meta = {
        "filename": "mirai.arm7",
        "sha256": "e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c",
        "file_type": "Linux ELF",
        "size_bytes": 65536,
        "signature": "Mirai",
        "tags": ["arm", "cowrie", "elf", "honeypot", "Mirai"]
    }
    triage_data = {
        "spawned_processes": [],
        "dropped_files": [],
        "persistence_hooks": [],
        "static_indicators": {
            "indicators": {"keywords": {"scan": 15, "ssh": 20}, "ips": ["198.51.100.1"], "urls": []}
        }
    }

    synthesis = _deterministic_fallback_synthesis(sample_meta, triage_data)
    # HUN-24: Family must be recognized as Mirai Botnet, not generic Linux Suspicious Executable
    assert "Mirai" in synthesis.malware_family
    assert synthesis.threat_classification == "Botnet"
    assert synthesis.threat_severity_score >= 8


def test_no_cloud_architecture_leakage_hun25():
    sample_meta = {
        "filename": "sample.bin",
        "sha256": "1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        "file_type": "Linux ELF",
        "size_bytes": 12345
    }
    triage_data = {
        "spawned_processes": [],
        "dropped_files": [],
        "persistence_hooks": [],
        "static_indicators": {}
    }

    synthesis = _deterministic_fallback_synthesis(sample_meta, triage_data)
    summary = synthesis.executive_summary
    # HUN-25: Invariant check - No internal cloud backend infrastructure leaks
    assert "Cloud Detonation Host" not in summary
    assert "designated for" not in summary
    assert "Option B" not in summary
    assert "GCP" not in summary


def test_yara_rule_generation_hun26():
    sample_meta = {
        "filename": "botnet.elf",
        "sha256": "e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c",
        "file_type": "Linux ELF",
        "size_bytes": 50000,
        "signature": "Mirai"
    }
    triage_data = {
        "spawned_processes": [],
        "dropped_files": [],
        "persistence_hooks": [],
        "static_indicators": {
            "indicators": {
                "keywords": {"busybox": 5},
                "ips": ["198.51.100.12"],
                "urls": ["http://cnc.botnet.example/bins"]
            },
            "sample_strings": ["/bin/busybox", "POST /login", "attack_udp"],
            "xor_deobfuscation": {
                "is_xor_obfuscated": True,
                "detected_keys": [
                    {
                        "key_hex": "0x22",
                        "sample_decoded_strings": ["/dev/watchdog", "admin:admin", "telnetd"]
                    }
                ]
            }
        }
    }

    synthesis = _deterministic_fallback_synthesis(sample_meta, triage_data)
    yara = synthesis.yara_rule_candidate

    # HUN-26: Must NOT just match 4-byte generic ELF magic with no other constraints
    assert "$elf_header = { 7F 45 4C 46 }" not in yara or "filesize" in yara
    # Dynamic date should not be hardcoded to 2026-09-13
    assert "filesize >=" in yara
    assert "filesize <=" in yara
    # Contains extracted strings or endpoints
    assert "$s1" in yara


def test_mitre_and_xor_mapping_hun28_hun29():
    sample_meta = {
        "filename": "mirai.bin",
        "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        "file_type": "Linux ELF",
        "size_bytes": 45000,
        "signature": "Mirai"
    }
    triage_data = {
        "spawned_processes": [],
        "dropped_files": [],
        "persistence_hooks": ["0 * * * * /tmp/update.sh"],
        "static_indicators": {
            "indicators": {
                "keywords": {"ssh": 12, "scan": 15},
                "ips": ["198.51.100.99"],
                "urls": []
            },
            "xor_deobfuscation": {
                "is_xor_obfuscated": True,
                "detected_keys": [{"key_hex": "0x22"}]
            }
        }
    }

    synthesis = _deterministic_fallback_synthesis(sample_meta, triage_data)
    technique_ids = [m.technique_id for m in synthesis.mitre_attack_techniques]

    # Verify enriched techniques
    assert "T1498" in technique_ids  # DDoS / Network DoS
    assert "T1046" in technique_ids  # Network Service Discovery
    assert "T1110" in technique_ids  # Brute Force
    assert "T1027" in technique_ids  # Obfuscated Files or Information (XOR)
    assert "T1053.003" in technique_ids  # Cron persistence
