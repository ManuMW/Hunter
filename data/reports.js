/**
 * Hunter Security Labs - Cataloged Threat Intelligence Reports
 * Generated from live detonation runs in Hunter
 */

const THREAT_REPORTS = [
    {
        "id": "e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c",
        "sha256": "e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c",
        "title": "Threat Analysis Report - e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c",
        "family": "Mirai Botnet",
        "category": "BOTNET",
        "severity": "CRITICAL",
        "severityScore": "8/10",
        "date": "2026-10-03 07:53:13 UTC",
        "author": "Hunter Research Team",
        "readTime": "4 min read",
        "summary": "Static binary analysis and reverse engineering triage was conducted on sample 'e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c' (Linux ELF Binary, 105520 bytes). The sample is classified as Mirai Botnet (Botnet) with an assessed threat severity score of 8/10. Observed behavioral signatures include 0 SSH authentication markers and 0 automated scanning routines characteristic of distributed denial-of-service botnets. Cryptographic deobfuscation successfully recovered concealed botnet command strings across 2 XOR key(s). Forensic telemetry and binary structural decomposition have been cataloged for defensive detection and threat hunting.",
        "tags": [
            "TROJAN",
            "LINUX SUSPICIOUS EXECUTABLE",
            "SEVERITY_6"
        ],
        "mitre": [],
        "iocs": [
            {
                "type": "sha256",
                "value": "e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c",
                "description": "Primary sample SHA-256"
            },
            {
                "type": "md5",
                "value": "4997020e5ad2fd3b8b5b9fadcce689d2",
                "description": "Primary sample MD5"
            }
        ],
        "behavior": {
            "processTree": [
                "Execution: Sample type: Linux ELF Binary"
            ],
            "droppedPayloads": []
        },
        "yaraRule": "rule Linux_e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c {\n    meta:\n        description = \"Automated detection rule for e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c\"\n        author = \"Threat Research Pipeline\"\n        date = \"2026-09-13\"\n        hash = \"e97af0f7cc5e9f9051e68b7834e9c59ba1633d58a18475d4663add0e3da7300c\"\n    strings:\n        $magic = { 7F 45 4C 46 }\n    condition:\n        uint32(0) == 0x464c457f and any of them\n}"
    }
];
