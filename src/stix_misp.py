"""
Threat Intelligence Export Serializer (STIX 2.1 & MISP)
Provides standard machine-readable cyber threat intelligence formats for
ingestion into SIEMs/SOARs (Splunk, Elastic, Sentinel, OpenCTI, MISP).
Adheres to HUN-12.
"""

import uuid
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional


HUNTER_IDENTITY_ID = "identity--f78b17b0-7b24-4f4c-8854-3bf1c8e19191"


def get_iso_timestamp(date_str: Optional[str] = None) -> str:
    if date_str:
        try:
            dt = datetime.strptime(date_str.strip(), "%Y-%m-%d")
            return dt.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        except Exception:
            pass
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def generate_stix21_bundle(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Serializes a Hunter threat report dictionary into a valid OASIS STIX 2.1 Bundle.
    Includes Identity, Malware, Indicators (hashes, IOCs, YARA), Attack-Patterns (MITRE),
    and Relationship SROs.
    """
    sha256 = report.get("sha256") or report.get("id", "unknown")
    family = report.get("family") or "Unclassified Threat"
    category = (report.get("category") or "MALWARE").lower()
    summary = report.get("summary") or f"Threat report for {sha256}"
    created_time = get_iso_timestamp(report.get("date"))

    # Map category to standard STIX malware-types
    valid_malware_types = {
        "botnet": "botnet",
        "trojan": "trojan",
        "ransomware": "ransomware",
        "cryptominer": "miner",
        "miner": "miner",
        "dropper": "dropper",
        "backdoor": "backdoor",
        "worm": "worm",
        "rootkit": "rootkit",
        "stealer": "spyware",
        "spyware": "spyware"
    }
    stix_malware_type = valid_malware_types.get(category, "malware")

    objects: List[Dict[str, Any]] = []

    # 1. Author Identity SDO
    identity_sdo = {
        "type": "identity",
        "spec_version": "2.1",
        "id": HUNTER_IDENTITY_ID,
        "created": created_time,
        "modified": created_time,
        "name": "Hunter Security Labs",
        "description": "Automated Cloud Sandbox Detonation & Linux Threat Research",
        "identity_class": "organization"
    }
    objects.append(identity_sdo)

    # 2. Malware SDO
    malware_id = f"malware--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.malware.{family}.{sha256}')}"
    malware_sdo = {
        "type": "malware",
        "spec_version": "2.1",
        "id": malware_id,
        "created": created_time,
        "modified": created_time,
        "name": family,
        "is_family": True,
        "malware_types": [stix_malware_type],
        "description": summary,
        "created_by_ref": HUNTER_IDENTITY_ID
    }
    objects.append(malware_sdo)

    # 3. Primary File SHA-256 Indicator SDO
    indicator_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.indicator.sha256.{sha256}')}"
    indicator_sdo = {
        "type": "indicator",
        "spec_version": "2.1",
        "id": indicator_id,
        "created": created_time,
        "modified": created_time,
        "name": f"Malicious Sample SHA-256: {sha256[:16]}...",
        "description": f"File hash observed for {family} ELF binary.",
        "indicator_types": ["malicious-activity"],
        "pattern": f"[file:hashes.'SHA-256' = '{sha256}']",
        "pattern_type": "stix",
        "pattern_version": "2.1",
        "valid_from": created_time,
        "created_by_ref": HUNTER_IDENTITY_ID
    }
    objects.append(indicator_sdo)

    # Relationship: Indicator -> indicates -> Malware
    objects.append({
        "type": "relationship",
        "spec_version": "2.1",
        "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.rel.indicates.{indicator_id}.{malware_id}')}",
        "created": created_time,
        "modified": created_time,
        "relationship_type": "indicates",
        "source_ref": indicator_id,
        "target_ref": malware_id,
        "created_by_ref": HUNTER_IDENTITY_ID
    })

    # 4. Secondary IOC Indicators
    for ioc in report.get("iocs", []):
        ioc_val = ioc.get("value", "").strip()
        ioc_type = ioc.get("type", "").lower()
        if not ioc_val or ioc_val == sha256:
            continue

        pattern = None
        if ioc_type in ["md5"]:
            pattern = f"[file:hashes.'MD5' = '{ioc_val}']"
        elif ioc_type in ["sha1"]:
            pattern = f"[file:hashes.'SHA-1' = '{ioc_val}']"
        elif ioc_type in ["ipv4", "ip", "c2"]:
            pattern = f"[ipv4-addr:value = '{ioc_val}']"
        elif ioc_type in ["domain", "url"]:
            pattern = f"[domain-name:value = '{ioc_val}']"

        if pattern:
            sec_ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.indicator.ioc.{ioc_val}')}"
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": sec_ind_id,
                "created": created_time,
                "modified": created_time,
                "name": f"Observed IOC: {ioc_val}",
                "description": ioc.get("description", "Indicator of Compromise extracted during analysis"),
                "indicator_types": ["malicious-activity"],
                "pattern": pattern,
                "pattern_type": "stix",
                "pattern_version": "2.1",
                "valid_from": created_time,
                "created_by_ref": HUNTER_IDENTITY_ID
            })
            # Relationship
            objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.rel.indicates.{sec_ind_id}.{malware_id}')}",
                "created": created_time,
                "modified": created_time,
                "relationship_type": "indicates",
                "source_ref": sec_ind_id,
                "target_ref": malware_id,
                "created_by_ref": HUNTER_IDENTITY_ID
            })

    # 5. MITRE ATT&CK Attack Patterns
    for mitre in report.get("mitre", []):
        tech_id = mitre.get("id", "").strip()
        tech_name = mitre.get("name") or tech_id
        if not tech_id:
            continue

        attack_id = f"attack-pattern--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.attack.{tech_id}')}"
        clean_url_id = tech_id.replace(".", "/")
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": attack_id,
            "created": created_time,
            "modified": created_time,
            "name": tech_name,
            "description": f"MITRE ATT&CK technique {tech_id} ({mitre.get('tactic', 'TTP')}) identified during sandbox triage.",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{clean_url_id}/"
                }
            ],
            "created_by_ref": HUNTER_IDENTITY_ID
        })

        # Relationship: Malware -> uses -> Attack Pattern
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.rel.uses.{malware_id}.{attack_id}')}",
            "created": created_time,
            "modified": created_time,
            "relationship_type": "uses",
            "source_ref": malware_id,
            "target_ref": attack_id,
            "created_by_ref": HUNTER_IDENTITY_ID
        })

    # 6. YARA Rule Indicator (if present)
    yara_rule = report.get("yaraRule", "").strip()
    if yara_rule:
        yara_ind_id = f"indicator--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.indicator.yara.{sha256}')}"
        objects.append({
            "type": "indicator",
            "spec_version": "2.1",
            "id": yara_ind_id,
            "created": created_time,
            "modified": created_time,
            "name": f"YARA Candidate Rule: {family}",
            "description": f"Automated YARA detection rule synthesized for {family}.",
            "indicator_types": ["malicious-activity"],
            "pattern": yara_rule,
            "pattern_type": "yara",
            "valid_from": created_time,
            "created_by_ref": HUNTER_IDENTITY_ID
        })
        objects.append({
            "type": "relationship",
            "spec_version": "2.1",
            "id": f"relationship--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.rel.indicates.{yara_ind_id}.{malware_id}')}",
            "created": created_time,
            "modified": created_time,
            "relationship_type": "indicates",
            "source_ref": yara_ind_id,
            "target_ref": malware_id,
            "created_by_ref": HUNTER_IDENTITY_ID
        })

    # STIX 2.1 Bundle Root
    bundle_id = f"bundle--{uuid.uuid5(uuid.NAMESPACE_DNS, f'hunter.bundle.{sha256}')}"
    return {
        "type": "bundle",
        "id": bundle_id,
        "spec_version": "2.1",
        "objects": objects
    }


def generate_misp_event(report: Dict[str, Any]) -> Dict[str, Any]:
    """
    Serializes a Hunter threat report dictionary into a standard MISP Event structure.
    """
    sha256 = report.get("sha256") or report.get("id", "unknown")
    family = report.get("family") or "Unclassified Threat"
    title = report.get("title") or f"Threat Report: {family}"
    severity = (report.get("severity") or "HIGH").upper()
    date_str = report.get("date") or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # Threat level mapping: 1=High, 2=Medium, 3=Low, 4=Undefined
    threat_level_map = {
        "CRITICAL": "1",
        "HIGH": "1",
        "MEDIUM": "2",
        "LOW": "3",
        "BENIGN": "3"
    }
    threat_level = threat_level_map.get(severity, "2")

    attributes: List[Dict[str, Any]] = [
        {
            "type": "sha256",
            "category": "Payload delivery",
            "value": sha256,
            "comment": f"Primary SHA-256 for {family} ELF sample",
            "to_ids": True,
            "disable_correlation": False
        }
    ]

    # Additional IOC attributes
    for ioc in report.get("iocs", []):
        val = ioc.get("value", "").strip()
        ioc_type = ioc.get("type", "").lower()
        if not val or val == sha256:
            continue

        misp_type = "other"
        misp_category = "Artifacts dropped"
        if ioc_type in ["md5"]:
            misp_type = "md5"
            misp_category = "Payload delivery"
        elif ioc_type in ["sha1"]:
            misp_type = "sha1"
            misp_category = "Payload delivery"
        elif ioc_type in ["ipv4", "ip", "c2"]:
            misp_type = "ip-dst"
            misp_category = "Network activity"
        elif ioc_type in ["domain"]:
            misp_type = "domain"
            misp_category = "Network activity"

        attributes.append({
            "type": misp_type,
            "category": misp_category,
            "value": val,
            "comment": ioc.get("description", "Observed indicator"),
            "to_ids": True,
            "disable_correlation": False
        })

    # YARA rule attribute
    yara_rule = report.get("yaraRule", "").strip()
    if yara_rule:
        attributes.append({
            "type": "yara",
            "category": "Artifacts dropped",
            "value": yara_rule,
            "comment": f"Synthesized detection rule for {family}",
            "to_ids": False,
            "disable_correlation": True
        })

    # Tags
    tags: List[Dict[str, str]] = [
        {"name": "tlp:clear"},
        {"name": f"hunter:family=\"{family}\""},
        {"name": f"hunter:severity=\"{severity}\""},
        {"name": f"hunter:category=\"{report.get('category', 'MALWARE')}\""}
    ]

    for mitre in report.get("mitre", []):
        tech_id = mitre.get("id", "").strip()
        if tech_id:
            tags.append({"name": f"misp-galaxy:mitre-attack-pattern=\"{tech_id}\""})

    for tag in report.get("tags", []):
        if tag:
            tags.append({"name": f"threat-intel:{tag.lower()}"})

    event_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"hunter.misp.event.{sha256}"))

    return {
        "Event": {
            "uuid": event_uuid,
            "info": title,
            "date": date_str,
            "threat_level_id": threat_level,
            "analysis": "2",  # Completed
            "distribution": "3",  # All communities
            "published": True,
            "orgc": {
                "name": "Hunter Security Labs",
                "uuid": "f78b17b0-7b24-4f4c-8854-3bf1c8e19191"
            },
            "Attribute": attributes,
            "Tag": tags
        }
    }
