import json
import logging
import re
import time
from datetime import datetime, timezone
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
- MalwareBazaar Signature: {sample_meta.get('signature', 'Unclassified')}
- Threat Tags: {', '.join(sample_meta.get('tags', [])) if sample_meta.get('tags') else 'None'}
- First Seen: {sample_meta.get('first_seen', 'N/A')}

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

Static Decomposition Findings (ELF Headers, Extracted Strings, Embedded Keywords, XOR Deobfuscation):
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
    
    max_retries = 3
    retry_delay = 1.0
    for attempt in range(1, max_retries + 1):
        try:
            with httpx.Client(timeout=45.0) as client:
                resp = client.post(url, json=payload)
                if resp.status_code in [429, 500, 502, 503, 504]:
                    logger.warning(
                        f"Gemini API returned HTTP {resp.status_code} on attempt {attempt}/{max_retries}: {resp.text}"
                    )
                    if attempt < max_retries:
                        time.sleep(retry_delay)
                        retry_delay *= 2
                        continue
                resp.raise_for_status()
                data = resp.json()
                
                candidate_text = data["candidates"][0]["content"]["parts"][0]["text"]
                parsed_json = json.loads(candidate_text)
                return ThreatAnalysisSynthesis.model_validate(parsed_json)
                
        except (httpx.RequestError, httpx.TimeoutException) as req_err:
            logger.warning(f"Gemini API network error on attempt {attempt}/{max_retries}: {req_err}")
            if attempt < max_retries:
                time.sleep(retry_delay)
                retry_delay *= 2
                continue
        except Exception as e:
            logger.error(f"Gemini API processing failed on attempt {attempt}/{max_retries}: {e}")
            break

    logger.warning("Gemini API unavailable or retries exhausted. Using deterministic fallback synthesis.")
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

    # Metadata & Family Attribution (HUN-24)
    signature = (sample_meta.get("signature") or "").strip()
    tags = sample_meta.get("tags") or []
    sig_lower = signature.lower()
    tags_lower = [str(t).lower() for t in tags]

    # XOR Deobfuscation Findings (HUN-29)
    xor_decomp = static_data.get("xor_deobfuscation", {})
    is_xor = xor_decomp.get("is_xor_obfuscated", False)
    detected_keys = xor_decomp.get("detected_keys", [])
    deobf_ips = xor_decomp.get("deobfuscated_ips", [])
    deobf_urls = xor_decomp.get("deobfuscated_urls", [])

    is_scanner_botnet = (
        keywords.get("ssh", 0) > 10 or 
        keywords.get("telnet", 0) > 5 or 
        keywords.get("scan", 0) > 10 or 
        keywords.get("flood", 0) > 0 or
        keywords.get("mirai", 0) > 0 or
        "mirai" in sig_lower or
        "mirai" in tags_lower or
        "botnet" in tags_lower or
        "gafgyt" in sig_lower or
        "bashlite" in sig_lower or
        "mozi" in sig_lower
    )
    is_miner = (
        keywords.get("miner", 0) > 0 or 
        keywords.get("wallet", 0) > 0 or 
        keywords.get("stratum", 0) > 0 or 
        "coinminer" in sig_lower or
        "miner" in tags_lower or
        any("miner" in str(p).lower() for p in processes + dropped)
    )
    is_dropper = (
        keywords.get("dropper", 0) > 0 or 
        keywords.get("wget", 0) > 0 or 
        keywords.get("curl", 0) > 0 or
        "dropper" in sig_lower or
        "downloader" in tags_lower
    )

    has_cron = len(persistence) > 0 or any("cron" in str(p) for p in paths)

    severity = 6
    if "mirai" in sig_lower or "mirai" in tags_lower:
        family = "Mirai Botnet"
        classification = "Botnet"
        severity = 8
    elif "gafgyt" in sig_lower or "bashlite" in sig_lower or "gafgyt" in tags_lower or "bashlite" in tags_lower:
        family = "Gafgyt / BASHLITE Botnet"
        classification = "Botnet"
        severity = 8
    elif "mozi" in sig_lower or "mozi" in tags_lower:
        family = "Mozi Botnet"
        classification = "Botnet"
        severity = 8
    elif is_scanner_botnet:
        classification = "Botnet"
        family = f"{signature} Botnet" if (signature and signature != "Unclassified") else "Linux Network Scanner / Botnet"
        severity = 8
    elif is_miner:
        classification = "Cryptominer"
        family = signature if (signature and signature != "Unclassified") else "Linux Cryptominer"
        severity = 7
    elif is_dropper:
        classification = "Dropper"
        family = signature if (signature and signature != "Unclassified") else "Linux Downloader / Dropper"
        severity = 7
    elif signature and signature != "Unclassified":
        family = signature
        classification = "Trojan"
        severity = 7
    else:
        classification = "Trojan"
        family = "Linux Suspicious Executable"
        severity = 6

    if has_cron:
        severity = min(10, severity + 1)

    # MITRE ATT&CK Mapping (HUN-28)
    mitre = []
    if is_scanner_botnet:
        mitre.append(MitreTechnique(
            technique_id="T1498",
            technique_name="Network Denial of Service",
            tactic="Impact",
            evidence="Identified automated network packet flooding or distributed denial-of-service command sequences."
        ))
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
    if is_xor:
        key_hexes = ", ".join(k.get("key_hex", "") for k in detected_keys)
        mitre.append(MitreTechnique(
            technique_id="T1027",
            technique_name="Obfuscated Files or Information",
            tactic="Defense Evasion",
            evidence=f"Deobfuscated encoded botnet strings utilizing single-byte XOR key(s): {key_hexes}"
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
    elif is_scanner_botnet or is_dropper:
        mitre.append(MitreTechnique(
            technique_id="T1059.004",
            technique_name="Command and Scripting Interpreter: Unix Shell",
            tactic="Execution",
            evidence="Binary static analysis revealed execution bindings to /bin/sh or command interpreters"
        ))
    if ips or urls or deobf_ips or deobf_urls:
        mitre.append(MitreTechnique(
            technique_id="T1071",
            technique_name="Application Layer Protocol",
            tactic="Command and Control",
            evidence=f"Extracted hardcoded remote endpoints ({len(ips + deobf_ips)} IPs, {len(urls + deobf_urls)} URLs)"
        ))

    behaviors = []
    if is_scanner_botnet:
        behaviors.append(ObservedBehavior(
            category="Discovery",
            description="Embedded network port discovery and authentication routines.",
            evidence=f"Identified {keywords.get('ssh', 0)} SSH references and {keywords.get('scan', 0)} scan routines."
        ))
    if ips or deobf_ips:
        active_ips = list(dict.fromkeys(ips + deobf_ips))
        behaviors.append(ObservedBehavior(
            category="Command and Control",
            description="Hardcoded external IPv4 addresses embedded in executable data sections.",
            evidence=f"Discovered IP endpoints: {', '.join(active_ips[:4])}"
        ))
    if is_xor:
        behaviors.append(ObservedBehavior(
            category="Defense Evasion",
            description="Concealed internal operational strings using single-byte XOR encryption.",
            evidence=f"Extracted {len(detected_keys)} XOR key(s): {', '.join(k.get('key_hex', '') for k in detected_keys)}"
        ))
    if not behaviors:
        behaviors.append(ObservedBehavior(
            category="Execution",
            description="Static binary analysis and telemetry decomposition.",
            evidence=f"Sample type: {sample_meta.get('file_type')}"
        ))

    all_ips = list(dict.fromkeys(ips + deobf_ips))
    all_urls = list(dict.fromkeys(urls + deobf_urls))

    iocs = [
        IndicatorOfCompromise(type="sha256", value=sample_meta.get("sha256", ""), description="Primary sample SHA-256"),
        IndicatorOfCompromise(type="md5", value=sample_meta.get("md5", ""), description="Primary sample MD5")
    ]
    for ip in all_ips[:10]:
        iocs.append(IndicatorOfCompromise(type="ip", value=ip, description="Discovered external IP endpoint"))
    for url in all_urls[:8]:
        iocs.append(IndicatorOfCompromise(type="url", value=url, description="Discovered URL indicator"))
    for p in paths[:5]:
        iocs.append(IndicatorOfCompromise(type="file_path", value=p, description="Discovered filesystem path"))

    # High-Fidelity YARA Rule Generation (HUN-26)
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    sha256 = sample_meta.get("sha256", "unknown")
    safe_family_id = re.sub(r'[^a-zA-Z0-9_]', '_', family).strip('_')[:20]
    if not safe_family_id or not safe_family_id[0].isalpha():
        safe_family_id = f"Threat_{safe_family_id}"
    safe_rule_name = f"Linux_{safe_family_id}_{sha256[:8]}"

    GENERIC_PATTERNS = {
        "libc", "glibc", "__libc", "stdout", "stdin", "stderr", "environ",
        "ptimer", "error", "malloc", "free", "printf", "exit", "abort",
        "__gmon_start__", "_init", "_fini", "gcc", "gnu"
    }
    candidate_strings = []
    for dk in detected_keys:
        for dec_str in dk.get("sample_decoded_strings", []):
            clean = dec_str.strip()
            if len(clean) >= 5 and clean not in candidate_strings:
                if not any(g in clean.lower() for g in GENERIC_PATTERNS):
                    candidate_strings.append(clean)
    for u in all_urls:
        if u not in candidate_strings:
            candidate_strings.append(u)
    for ip in all_ips:
        if ip not in candidate_strings:
            candidate_strings.append(ip)
    for s in sample_strings:
        clean = s.strip()
        if len(clean) >= 6 and clean not in candidate_strings:
            if not any(g in clean.lower() for g in GENERIC_PATTERNS):
                if sum(c.isalnum() for c in clean) >= 4:
                    candidate_strings.append(clean)

    yara_string_lines = []
    for idx, s in enumerate(candidate_strings[:6], 1):
        escaped = s.replace("\\", "\\\\").replace('"', '\\"')
        yara_string_lines.append(f'        $s{idx} = "{escaped}" ascii')

    size_bytes = sample_meta.get("size_bytes", 10000)
    min_size = max(100, int(size_bytes * 0.6))
    max_size = int(size_bytes * 1.6) + 2048

    if yara_string_lines:
        num_required = min(2, len(yara_string_lines))
        condition_block = f"""        uint32(0) == 0x464c457f and
        filesize >= {min_size} and filesize <= {max_size} and
        {num_required} of ($s*)"""
        strings_block = chr(10).join(yara_string_lines)
    else:
        condition_block = f"""        uint32(0) == 0x464c457f and
        filesize >= {min_size} and filesize <= {max_size}"""
        strings_block = '        $elf_header = { 7F 45 4C 46 }'

    yara = f"""rule {safe_rule_name} {{
    meta:
        description = "Detection rule for {family} ({classification}) - {sha256}"
        author = "Hunter Threat Research Team"
        date = "{now_str}"
        hash = "{sha256}"
        malware_family = "{family}"
        severity = "{severity}/10"
    strings:
{strings_block}
    condition:
{condition_block}
}}"""

    # Clean UI Abstraction Summary (HUN-25)
    summary = (
        f"Static binary analysis and reverse engineering triage was conducted on sample '{sample_meta.get('filename')}' "
        f"({sample_meta.get('file_type')}, {sample_meta.get('size_bytes')} bytes). "
        f"The sample is classified as {family} ({classification}) with an assessed threat severity score of {min(severity, 10)}/10. "
        + (f"Static and deobfuscated indicator extraction revealed {len(all_ips)} external IP endpoints and {len(all_urls)} target URLs. " if all_ips or all_urls else "")
        + (f"Observed behavioral signatures include {keywords.get('ssh', 0)} SSH authentication markers and {keywords.get('scan', 0)} automated scanning routines characteristic of distributed denial-of-service botnets. " if is_scanner_botnet else "")
        + (f"Cryptographic deobfuscation successfully recovered concealed botnet command strings across {len(detected_keys)} XOR key(s). " if is_xor else "")
        + "Forensic telemetry and binary structural decomposition have been cataloged for defensive detection and threat hunting."
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
