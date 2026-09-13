import json
import logging
from typing import List, Dict, Any, Optional
import httpx
from pydantic import BaseModel, Field

from src.config import GEMINI_API_KEY, GEMINI_MODEL

logger = logging.getLogger(__name__)


class MitreTechnique(BaseModel):
    technique_id: str = Field(description="MITRE ATT&CK technique ID, e.g., T1053.003")
    technique_name: str = Field(description="Name of the technique, e.g., Scheduled Task/Job: Cron")
    tactic: str = Field(description="MITRE ATT&CK tactic category, e.g., Persistence")
    evidence: str = Field(description="Forensic evidence observed during sandbox detonation")


class ObservedBehavior(BaseModel):
    category: str = Field(description="Behavior category, e.g., Persistence, Evasion, Discovery, Execution")
    description: str = Field(description="Clear explanation of the observed behavior")
    evidence: str = Field(description="Process command or filesystem artifact backing this behavior")


class IndicatorOfCompromise(BaseModel):
    type: str = Field(description="Type of IoC: sha256, md5, file_path, ip, domain, cron_job")
    value: str = Field(description="The indicator value")
    description: str = Field(description="Context or role of the indicator")


class ThreatAnalysisSynthesis(BaseModel):
    malware_family: str = Field(description="Identified or suspected malware family or type")
    threat_severity_score: int = Field(ge=1, le=10, description="Severity rating from 1 (Benign) to 10 (Critical)")
    threat_classification: str = Field(description="High-level category: Cryptominer, Ransomware, Trojan, Rootkit, Botnet, Downloader, or Benign")
    executive_summary: str = Field(description="2-3 paragraphs explaining the sample's capabilities and risks")
    mitre_attack_techniques: List[MitreTechnique] = Field(default_factory=list)
    observed_behaviors: List[ObservedBehavior] = Field(default_factory=list)
    indicators_of_compromise: List[IndicatorOfCompromise] = Field(default_factory=list)
    yara_rule_candidate: str = Field(description="Suggested YARA rule candidate for detection")
    confidence_score: float = Field(ge=0.0, le=1.0, description="Confidence score from 0.0 to 1.0")


GEMINI_RESPONSE_SCHEMA = {
    "type": "OBJECT",
    "properties": {
        "malware_family": {"type": "STRING", "description": "Identified or suspected malware family"},
        "threat_severity_score": {"type": "INTEGER", "description": "Severity rating from 1 to 10"},
        "threat_classification": {"type": "STRING", "description": "High-level classification (Cryptominer, Trojan, Botnet, Rootkit, or Benign)"},
        "executive_summary": {"type": "STRING", "description": "2-3 paragraphs synthesizing sample behavior and risks"},
        "mitre_attack_techniques": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "technique_id": {"type": "STRING"},
                    "technique_name": {"type": "STRING"},
                    "tactic": {"type": "STRING"},
                    "evidence": {"type": "STRING"}
                },
                "required": ["technique_id", "technique_name", "tactic", "evidence"]
            }
        },
        "observed_behaviors": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "category": {"type": "STRING"},
                    "description": {"type": "STRING"},
                    "evidence": {"type": "STRING"}
                },
                "required": ["category", "description", "evidence"]
            }
        },
        "indicators_of_compromise": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "type": {"type": "STRING"},
                    "value": {"type": "STRING"},
                    "description": {"type": "STRING"}
                },
                "required": ["type", "value", "description"]
            }
        },
        "yara_rule_candidate": {"type": "STRING", "description": "Suggested YARA rule candidate for detection"},
        "confidence_score": {"type": "NUMBER", "description": "Confidence score from 0.0 to 1.0"}
    },
    "required": [
        "malware_family",
        "threat_severity_score",
        "threat_classification",
        "executive_summary",
        "mitre_attack_techniques",
        "observed_behaviors",
        "indicators_of_compromise",
        "yara_rule_candidate",
        "confidence_score"
    ]
}


def synthesize_threat_report(
    sample_meta: Dict[str, Any],
    triage_data: Dict[str, Any],
    api_key: Optional[str] = None
) -> ThreatAnalysisSynthesis:
    """
    Sends forensic triage findings to Google AI Studio Gemini API with a strict JSON schema.
    Falls back to deterministic rule-based synthesis if no API key is provided.
    """
    key = api_key or GEMINI_API_KEY
    
    if not key or key == "your_google_ai_studio_api_key_here":
        logger.warning("No valid Google AI Studio API key provided. Using deterministic fallback synthesis.")
        return _deterministic_fallback_synthesis(sample_meta, triage_data)
        
    prompt = f"""
You are an elite Threat Intelligence and Malware Reverse Engineering Analyst.
Analyze the following forensic triage artifacts collected from an air-gapped 90-second Linux sandbox detonation.

Sample Metadata:
- Filename: {sample_meta.get('filename')}
- SHA256: {sample_meta.get('sha256')}
- File Type: {sample_meta.get('file_type')}
- File Size: {sample_meta.get('size_bytes')} bytes

Observed Execution Summary:
{json.dumps(triage_data.get('execution_summary', {}), indent=2)}

Spawned Processes:
{json.dumps(triage_data.get('spawned_processes', []), indent=2)}

Dropped Files in /tmp and staging locations:
{json.dumps(triage_data.get('dropped_files', []), indent=2)}

Persistence Hooks (Cron / Systemd):
{json.dumps(triage_data.get('persistence_hooks', []), indent=2)}

Network Indicators:
{json.dumps(triage_data.get('network_indicators', []), indent=2)}

Instructions:
1. Synthesize these findings into a rigorous Threat Intelligence analysis.
2. Map all concrete forensic observations to official MITRE ATT&CK techniques with exact technique IDs.
3. Extract all Indicators of Compromise (IoCs) including file hashes, dropped paths, and configuration artifacts.
4. Generate a syntactically valid YARA rule tailored to detect this sample's characteristics.
5. Adhere strictly to the requested JSON schema.
"""

    url = f"https://generativelanguage.googleapis.com/v1beta/models/{GEMINI_MODEL}:generateContent?key={key}"
    
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": prompt}
                ]
            }
        ],
        "generationConfig": {
            "response_mime_type": "application/json",
            "response_schema": GEMINI_RESPONSE_SCHEMA
        }
    }
    
    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(url, json=payload)
            resp.raise_for_status()
            data = resp.json()
            
            candidate_text = data["candidates"][0]["content"]["parts"][0]["text"]
            parsed_json = json.loads(candidate_text)
            return ThreatAnalysisSynthesis.model_validate(parsed_json)
            
    except Exception as e:
        logger.error(f"Gemini API request failed: {e}. Falling back to deterministic analysis.")
        return _deterministic_fallback_synthesis(sample_meta, triage_data)


def _deterministic_fallback_synthesis(
    sample_meta: Dict[str, Any],
    triage_data: Dict[str, Any]
) -> ThreatAnalysisSynthesis:
    """Generates an initial analysis based on extracted triage data when API is offline."""
    processes = triage_data.get("spawned_processes", [])
    dropped = triage_data.get("dropped_files", [])
    persistence = triage_data.get("persistence_hooks", [])
    
    # Heuristics
    is_miner = any("miner" in str(p).lower() or "pool" in str(p).lower() for p in processes + dropped)
    has_cron = len(persistence) > 0
    severity = 5
    if is_miner:
        severity += 2
    if has_cron:
        severity += 2
        
    family = "Suspicious Linux Cryptominer" if is_miner else "Generic Linux Suspicious Executable"
    classification = "Cryptominer" if is_miner else "Trojan"
    
    mitre = []
    if processes:
        mitre.append(MitreTechnique(
            technique_id="T1059.004",
            technique_name="Command and Scripting Interpreter: Unix Shell",
            tactic="Execution",
            evidence=f"Spawned {len(processes)} process(es)"
        ))
    if has_cron:
        mitre.append(MitreTechnique(
            technique_id="T1053.003",
            technique_name="Scheduled Task/Job: Cron",
            tactic="Persistence",
            evidence=f"Detected cron persistence entries: {', '.join(persistence[:2])}"
        ))
    if dropped:
        mitre.append(MitreTechnique(
            technique_id="T1105",
            technique_name="Ingress Tool Transfer",
            tactic="Command and Control",
            evidence=f"Dropped files in temporary staging: {', '.join(str(d.get('path')) for d in dropped[:3])}"
        ))
        
    behaviors = [
        ObservedBehavior(
            category="Execution",
            description="Sample executed in air-gapped sandbox environment.",
            evidence=f"Sample type: {sample_meta.get('file_type')}"
        )
    ]
    if persistence:
        behaviors.append(ObservedBehavior(
            category="Persistence",
            description="Installed persistence mechanism on local filesystem.",
            evidence=str(persistence[0])
        ))

    iocs = [
        IndicatorOfCompromise(type="sha256", value=sample_meta.get("sha256", ""), description="Sample SHA-256"),
        IndicatorOfCompromise(type="md5", value=sample_meta.get("md5", ""), description="Sample MD5")
    ]
    for d in dropped:
        if d.get("path"):
            iocs.append(IndicatorOfCompromise(type="file_path", value=d["path"], description="Dropped artifact path"))

    safe_name = sample_meta.get("filename", "sample").replace(".", "_").replace("-", "_")
    yara = f"""rule Linux_{safe_name} {{
    meta:
        description = "Automated detection rule for {sample_meta.get('sha256')}"
        author = "Threat Research Pipeline"
        date = "2026-09-13"
        hash = "{sample_meta.get('sha256')}"
    strings:
        $magic = {{ 7F 45 4C 46 }}
    condition:
        $magic at 0 and filesize < {max(sample_meta.get('size_bytes', 1000) * 2, 2048)}
}}"""

    summary = (
        f"Dynamic analysis was conducted on sample '{sample_meta.get('filename')}' "
        f"({sample_meta.get('file_type')}). During the 90-second air-gapped detonation run, "
        f"the sample initiated {len(processes)} process execution(s) and staged {len(dropped)} "
        f"artifact(s) into temporary filesystem directories. "
        + ("A persistence mechanism was identified via cron modifications. " if has_cron else "")
        + "Indicators have been extracted and mapped to corresponding MITRE ATT&CK techniques."
    )

    return ThreatAnalysisSynthesis(
        malware_family=family,
        threat_severity_score=min(severity, 10),
        threat_classification=classification,
        executive_summary=summary,
        mitre_attack_techniques=mitre,
        observed_behaviors=behaviors,
        indicators_of_compromise=iocs,
        yara_rule_candidate=yara,
        confidence_score=0.85
    )
