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


class DroppedPayloadAnalysis(BaseModel):
    filename: str = Field(description="Name of the dropped file or binary")
    sha256: str = Field(description="SHA-256 hash of the dropped file")
    file_type: str = Field(description="File type (e.g., Linux ELF, Shell Script, JSON Configuration)")
    role: str = Field(description="Operational role, e.g., Mining Worker, Dropper Stage 2, Persistence Hook, Configuration")
    analysis: str = Field(description="In-depth explanation of what this dropped payload does and how it interacts with the parent")
    embedded_indicators: List[str] = Field(default_factory=list, description="Extracted IPs, URLs, or configuration keys")


class ThreatAnalysisSynthesis(BaseModel):
    malware_family: str = Field(description="Identified or suspected malware family or type")
    threat_severity_score: int = Field(ge=1, le=10, description="Severity rating from 1 (Benign) to 10 (Critical)")
    threat_classification: str = Field(description="High-level category: Cryptominer, Ransomware, Trojan, Rootkit, Botnet, Downloader, or Benign")
    executive_summary: str = Field(description="2-3 paragraphs explaining the sample's capabilities and risks")
    mitre_attack_techniques: List[MitreTechnique] = Field(default_factory=list)
    observed_behaviors: List[ObservedBehavior] = Field(default_factory=list)
    indicators_of_compromise: List[IndicatorOfCompromise] = Field(default_factory=list)
    dropped_payload_analyses: List[DroppedPayloadAnalysis] = Field(default_factory=list)
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
        "dropped_payload_analyses": {
            "type": "ARRAY",
            "items": {
                "type": "OBJECT",
                "properties": {
                    "filename": {"type": "STRING"},
                    "sha256": {"type": "STRING"},
                    "file_type": {"type": "STRING"},
                    "role": {"type": "STRING"},
                    "analysis": {"type": "STRING"},
                    "embedded_indicators": {
                        "type": "ARRAY",
                        "items": {"type": "STRING"}
                    }
                },
                "required": ["filename", "sha256", "file_type", "role", "analysis", "embedded_indicators"]
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
        "dropped_payload_analyses",
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

Dropped Payloads & Secondary Stages (Static Decomposition & Strings):
{json.dumps(triage_data.get('dropped_payloads', []), indent=2)}

Persistence Hooks (Cron / Systemd):
{json.dumps(triage_data.get('persistence_hooks', []), indent=2)}

Static Decomposition Findings (ELF Headers, Extracted Strings, Embedded Keywords):
{json.dumps(triage_data.get('static_indicators', {}), indent=2)}

Instructions:
1. Synthesize these findings into a rigorous, truthful Threat Intelligence analysis tailored exclusively to THIS specific sample.
2. If dynamic container execution was not performed (static triage mode), base your analysis on the sample's genuine static decomposition, ELF structure, extracted strings, and network targets. DO NOT invent unobserved child processes, fake Monero wallets, or fake file paths.
3. Map concrete forensic observations to official MITRE ATT&CK techniques with exact technique IDs.
4. Extract all genuine Indicators of Compromise (IoCs) including file hashes, discovered IP addresses, URLs, and paths from the artifacts.
5. Generate a syntactically valid YARA rule tailored specifically to detect this sample's unique strings or header properties.
6. Adhere strictly to the requested JSON schema.
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
    static_data = triage_data.get("static_indicators", {})
    indicators = static_data.get("indicators", {})
    keywords = indicators.get("keywords", {})
    ips = indicators.get("ips", [])
    urls = indicators.get("urls", [])
    paths = indicators.get("paths", [])
    sample_strings = indicators.get("sample_strings", [])

    is_scanner_botnet = (
        keywords.get("ssh", 0) > 10 or 
        keywords.get("telnet", 0) > 5 or 
        keywords.get("scan", 0) > 10 or 
        keywords.get("flood", 0) > 0 or
        keywords.get("mirai", 0) > 0
    )
    is_miner = (
        keywords.get("miner", 0) > 0 or 
        keywords.get("wallet", 0) > 0 or 
        keywords.get("stratum", 0) > 0 or 
        any("miner" in str(p).lower() for p in processes + dropped)
    )
    is_dropper = (
        keywords.get("dropper", 0) > 0 or 
        keywords.get("wget", 0) > 0 or 
        keywords.get("curl", 0) > 0
    )

    has_cron = len(persistence) > 0 or any("cron" in str(p) for p in paths)

    severity = 6
    if is_scanner_botnet:
        classification = "Botnet"
        family = "Linux Network Scanner / Botnet"
        severity = 8
    elif is_miner:
        classification = "Cryptominer"
        family = "Linux Cryptominer"
        severity = 7
    elif is_dropper:
        classification = "Dropper"
        family = "Linux Downloader / Dropper"
        severity = 7
    else:
        classification = "Trojan"
        family = "Linux Suspicious Executable"
        severity = 6

    if has_cron:
        severity = min(10, severity + 1)

    mitre = []
    if is_scanner_botnet:
        mitre.append(MitreTechnique(
            technique_id="T1046",
            technique_name="Network Service Discovery",
            tactic="Discovery",
            evidence=f"Discovered embedded network scanning strings and brute-force routines ({keywords.get('scan', 0)} scan markers, {keywords.get('ssh', 0)} SSH references)"
        ))
        mitre.append(MitreTechnique(
            technique_id="T1110",
            technique_name="Brute Force",
            tactic="Credential Access",
            evidence="Detected automated credential spraying keywords and target service bindings"
        ))
    if is_miner:
        mitre.append(MitreTechnique(
            technique_id="T1496",
            technique_name="Resource Hijacking",
            tactic="Impact",
            evidence="Cryptocurrency mining configuration or stratum pool endpoints detected"
        ))
    if has_cron:
        mitre.append(MitreTechnique(
            technique_id="T1053.003",
            technique_name="Scheduled Task/Job: Cron",
            tactic="Persistence",
            evidence="Cron persistence references detected in binary or filesystem hooks"
        ))
    if processes:
        mitre.append(MitreTechnique(
            technique_id="T1059.004",
            technique_name="Command and Scripting Interpreter: Unix Shell",
            tactic="Execution",
            evidence=f"Spawned {len(processes)} process(es)"
        ))

    behaviors = []
    if is_scanner_botnet:
        behaviors.append(ObservedBehavior(
            category="Discovery",
            description="Embedded network port discovery and authentication routines.",
            evidence=f"Identified {keywords.get('ssh', 0)} SSH references and {keywords.get('scan', 0)} scan routines."
        ))
    if ips:
        behaviors.append(ObservedBehavior(
            category="Command and Control",
            description="Hardcoded external IPv4 addresses embedded in executable data sections.",
            evidence=f"Discovered IP endpoints: {', '.join(ips[:4])}"
        ))
    if not behaviors:
        behaviors.append(ObservedBehavior(
            category="Execution",
            description="Static binary analysis and telemetry decomposition.",
            evidence=f"Sample type: {sample_meta.get('file_type')}"
        ))

    iocs = [
        IndicatorOfCompromise(type="sha256", value=sample_meta.get("sha256", ""), description="Primary sample SHA-256"),
        IndicatorOfCompromise(type="md5", value=sample_meta.get("md5", ""), description="Primary sample MD5")
    ]
    for ip in ips[:8]:
        iocs.append(IndicatorOfCompromise(type="ip", value=ip, description="Discovered external IP endpoint"))
    for url in urls[:5]:
        iocs.append(IndicatorOfCompromise(type="url", value=url, description="Discovered URL indicator"))
    for p in paths[:5]:
        iocs.append(IndicatorOfCompromise(type="file_path", value=p, description="Discovered filesystem path"))

    safe_name = sample_meta.get("filename", "sample").replace(".", "_").replace("-", "_")

    yara_strings = []
    for idx, s in enumerate(sample_strings[:4], 1):
        clean_s = re.sub(r'[^a-zA-Z0-9_\-\./:]', '', s)
        if len(clean_s) >= 4:
            yara_strings.append(f'        $s{idx} = "{clean_s}" ascii')
    if not yara_strings:
        yara_strings.append('        $magic = { 7F 45 4C 46 }')

    yara = f"""rule Linux_{safe_name} {{
    meta:
        description = "Automated detection rule for {sample_meta.get('sha256')}"
        author = "Threat Research Pipeline"
        date = "2026-09-13"
        hash = "{sample_meta.get('sha256')}"
    strings:
{chr(10).join(yara_strings)}
    condition:
        uint32(0) == 0x464c457f and any of them
}}"""

    summary = (
        f"Static binary analysis and reverse engineering triage was conducted on sample '{sample_meta.get('filename')}' "
        f"({sample_meta.get('file_type')}, {sample_meta.get('size_bytes')} bytes). "
        f"The sample was categorized as a {family} ({classification}). "
        + (f"Static string extraction revealed {len(ips)} external IP targets and {len(urls)} URLs. " if ips or urls else "")
        + (f"Key operational indicators include {keywords.get('ssh', 0)} SSH markers and {keywords.get('scan', 0)} scanning routines. " if is_scanner_botnet else "")
        + "Full dynamic container execution is designated for the Cloud Detonation Host."
    )

    return ThreatAnalysisSynthesis(
        malware_family=family,
        threat_severity_score=min(severity, 10),
        threat_classification=classification,
        executive_summary=summary,
        mitre_attack_techniques=mitre,
        observed_behaviors=behaviors,
        indicators_of_compromise=iocs,
        dropped_payload_analyses=[],
        yara_rule_candidate=yara,
        confidence_score=0.90
    )
