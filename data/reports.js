/**
 * Hunter Security Labs - Cataloged Threat Intelligence Reports
 * Generated from live detonation runs in Hunter
 */

const THREAT_REPORTS = [
    {
        "id": "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96",
        "sha256": "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96",
        "title": "Threat Analysis Report: i486 (Mirai Botnet)",
        "family": "Mirai Botnet",
        "category": "BOTNET",
        "severity": "CRITICAL",
        "severityScore": "8/10",
        "date": "2026-10-03",
        "author": "Hunter Research Team",
        "readTime": "4 min read",
        "summary": "Static binary analysis and reverse engineering triage was conducted on sample 'i486' (Linux ELF Binary, 76886 bytes). The sample is classified as Mirai Botnet (Botnet) with an assessed threat severity score of 8/10. Static and deobfuscated indicator extraction revealed 1 external IP endpoints and 1 target URLs. Observed behavioral signatures include 0 SSH authentication markers and 0 automated scanning routines characteristic of distributed denial-of-service botnets. Forensic telemetry and binary structural decomposition have been cataloged for defensive detection and threat hunting.",
        "tags": [
            "BOTNET",
            "MIRAI BOTNET",
            "SEVERITY_8",
            "ELF",
            "MIRAI"
        ],
        "mitre": [
            {
                "id": "T1498",
                "name": "Network Denial of Service",
                "tactic": "Impact"
            },
            {
                "id": "T1046",
                "name": "Network Service Discovery",
                "tactic": "Discovery"
            },
            {
                "id": "T1110",
                "name": "Brute Force",
                "tactic": "Credential Access"
            },
            {
                "id": "T1059.004",
                "name": "Command and Scripting Interpreter: Unix Shell",
                "tactic": "Execution"
            },
            {
                "id": "T1071",
                "name": "Application Layer Protocol",
                "tactic": "Command and Control"
            }
        ],
        "iocs": [
            {
                "type": "sha256",
                "value": "ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96",
                "description": "Primary sample SHA-256"
            },
            {
                "type": "md5",
                "value": "fdaa18731b924c2a43751715389792d7",
                "description": "Primary sample MD5"
            },
            {
                "type": "ip",
                "value": "185.14.92.139",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "url",
                "value": "https://github.com/xmrig/xmrig/releases/download/v6.18.0/xmrig-6.18.0-linux-static-x64.tar.gz",
                "description": "Discovered URL indicator"
            },
            {
                "type": "file_path",
                "value": "/etc/os-release",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/proc/cpuinfo",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/dev/null",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/proc/version",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/bin/sh",
                "description": "Discovered filesystem path"
            }
        ],
        "behavior": {
            "processTree": [
                "Discovery: Identified 0 SSH references and 0 scan routines.",
                "Command and Control: Discovered IP endpoints: 185.14.92.139"
            ],
            "droppedPayloads": []
        },
        "yaraRule": "rule Linux_Mirai_Botnet_ee1667c9 {\n    meta:\n        description = \"Detection rule for Mirai Botnet (Botnet) - ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96\"\n        author = \"Hunter Threat Research Team\"\n        date = \"2026-10-03\"\n        hash = \"ee1667c977ac4224a395fd99ef857699193beb4fd44fb7d63d0776edc91cae96\"\n        malware_family = \"Mirai Botnet\"\n        severity = \"8/10\"\n    strings:\n        $s1 = \"https://github.com/xmrig/xmrig/releases/download/v6.18.0/xmrig-6.18.0-linux-static-x64.tar.gz\" ascii\n        $s2 = \"185.14.92.139\" ascii\n    condition:\n        uint32(0) == 0x464c457f and\n        filesize >= 46131 and filesize <= 125065 and\n        2 of ($s*)\n}"
    },
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
