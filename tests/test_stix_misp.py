import pytest
from src.stix_misp import generate_stix21_bundle, generate_misp_event


@pytest.fixture
def sample_report():
    return {
        "id": "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522",
        "sha256": "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522",
        "title": "Threat Analysis Report: Mirai",
        "family": "Mirai",
        "category": "BOTNET",
        "severity": "CRITICAL",
        "severityScore": "8/10",
        "date": "2026-09-17",
        "summary": "Mirai botnet variant targeting IoT devices.",
        "tags": ["BOTNET", "MIRAI", "SEVERITY_8"],
        "mitre": [
            {"id": "T1059.004", "name": "Unix Shell", "tactic": "Execution"},
            {"id": "T1027.002", "name": "Software Packing / Stripped Symbols", "tactic": "Defense Evasion"}
        ],
        "iocs": [
            {"type": "sha256", "value": "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522", "description": "Primary SHA-256"},
            {"type": "ipv4", "value": "198.51.100.23", "description": "C2 Server"}
        ],
        "behavior": {
            "processTree": ["Process executed."],
            "droppedPayloads": []
        },
        "yaraRule": "rule Mirai_Test { condition: true }"
    }


def test_stix21_bundle_generation(sample_report):
    bundle = generate_stix21_bundle(sample_report)

    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    assert bundle["id"].startswith("bundle--")
    assert "objects" in bundle

    types = [obj["type"] for obj in bundle["objects"]]
    assert "identity" in types
    assert "malware" in types
    assert "indicator" in types
    assert "attack-pattern" in types
    assert "relationship" in types

    # Check primary indicator
    indicators = [obj for obj in bundle["objects"] if obj["type"] == "indicator"]
    file_ind = next(i for i in indicators if "file:hashes.'SHA-256'" in i["pattern"])
    assert sample_report["sha256"] in file_ind["pattern"]

    # Check secondary C2 indicator
    c2_ind = next(i for i in indicators if "ipv4-addr:value" in i["pattern"])
    assert "198.51.100.23" in c2_ind["pattern"]

    # Check attack pattern
    attack_patterns = [obj for obj in bundle["objects"] if obj["type"] == "attack-pattern"]
    assert len(attack_patterns) == 2
    assert any(a["name"] == "Unix Shell" for a in attack_patterns)


def test_misp_event_generation(sample_report):
    misp = generate_misp_event(sample_report)

    assert "Event" in misp
    event = misp["Event"]
    assert event["published"] is True
    assert event["threat_level_id"] == "1"  # Critical/High
    assert "Attribute" in event

    attr_values = [a["value"] for a in event["Attribute"]]
    assert sample_report["sha256"] in attr_values
    assert "198.51.100.23" in attr_values
    assert "rule Mirai_Test { condition: true }" in attr_values

    tag_names = [t["name"] for t in event["Tag"]]
    assert "tlp:clear" in tag_names
    assert 'misp-galaxy:mitre-attack-pattern="T1059.004"' in tag_names
