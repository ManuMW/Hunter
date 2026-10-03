/**
 * Hunter Security Labs - Cataloged Threat Intelligence Reports
 * Generated from live detonation runs in Hunter
 */

const THREAT_REPORTS = [
    {
        "id": "08ff1a293519f919c4fce850a6794a4df1f1b12e4aa3d6a29ee2ae30ff948278",
        "sha256": "08ff1a293519f919c4fce850a6794a4df1f1b12e4aa3d6a29ee2ae30ff948278",
        "title": "Threat Analysis Report: arm5 (Mirai Botnet)",
        "family": "Mirai Botnet",
        "category": "BOTNET",
        "severity": "CRITICAL",
        "severityScore": "8/10",
        "date": "2026-10-03",
        "author": "Hunter Research Team",
        "readTime": "4 min read",
        "summary": "Static binary analysis and reverse engineering triage was conducted on sample 'arm5' (Linux ELF Binary, 5832888 bytes). The sample is classified as Mirai Botnet (Botnet) with an assessed threat severity score of 8/10. Static and deobfuscated indicator extraction revealed 13 external IP endpoints and 11 target URLs. Observed behavioral signatures include 13 SSH authentication markers and 0 automated scanning routines characteristic of distributed denial-of-service botnets. Forensic telemetry and binary structural decomposition have been cataloged for defensive detection and threat hunting.",
        "tags": [
            "BOTNET",
            "MIRAI BOTNET",
            "SEVERITY_8",
            "ELF",
            "GODDOSAGENT",
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
                "value": "08ff1a293519f919c4fce850a6794a4df1f1b12e4aa3d6a29ee2ae30ff948278",
                "description": "Primary sample SHA-256"
            },
            {
                "type": "md5",
                "value": "3704c645ed75d8c9b0ece769f67a7d8d",
                "description": "Primary sample MD5"
            },
            {
                "type": "ip",
                "value": "4.32.5.4",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "52.5.4.72",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "120.0.0.0",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "2.5.4.102",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "5.4.62.5",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "94.154.43.117",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "119.0.0.0",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "1.3.1.1",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "5.4.112.5",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "ip",
                "value": "1.2.2.1",
                "description": "Discovered external IP endpoint"
            },
            {
                "type": "url",
                "value": "http://slice",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "https://www.facebook.com/no",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "https://twitter.com/https://www.fbi.gov/type",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "https://www.bing.com/bufio:",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "http://crypto/tls:",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "http://Mozilla/5.0",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "https://www.google.com/https://www.reddit.com/proxy/tlsplusbypass.txt",
                "description": "Discovered URL indicator"
            },
            {
                "type": "url",
                "value": "https://no-cacheGoString01234567beEfFgGvnetedns0",
                "description": "Discovered URL indicator"
            },
            {
                "type": "file_path",
                "value": "/etc/hosts",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/usr/lib/locale/TZ/INADEQUATE_SECURITYINITIAL_WINDOW_SIZEProxy-Authorizationframe_data_stream_0",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/dev/urandom",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/usr/local/share/mime/globs2access-control-allow-headersaccess-control-allow-methodsinvalid",
                "description": "Discovered filesystem path"
            },
            {
                "type": "file_path",
                "value": "/dev/urandominvalid",
                "description": "Discovered filesystem path"
            }
        ],
        "behavior": {
            "processTree": [
                "Discovery: Identified 13 SSH references and 0 scan routines.",
                "Command and Control: Discovered IP endpoints: 4.32.5.4, 52.5.4.72, 120.0.0.0, 2.5.4.102"
            ],
            "droppedPayloads": []
        },
        "yaraRule": "rule Linux_Mirai_Botnet_08ff1a29 {\n    meta:\n        description = \"Detection rule for Mirai Botnet (Botnet) - 08ff1a293519f919c4fce850a6794a4df1f1b12e4aa3d6a29ee2ae30ff948278\"\n        author = \"Hunter Threat Research Team\"\n        date = \"2026-10-03\"\n        hash = \"08ff1a293519f919c4fce850a6794a4df1f1b12e4aa3d6a29ee2ae30ff948278\"\n        malware_family = \"Mirai Botnet\"\n        severity = \"8/10\"\n    strings:\n        $s1 = \"http://slice\" ascii\n        $s2 = \"https://www.facebook.com/no\" ascii\n        $s3 = \"https://twitter.com/https://www.fbi.gov/type\" ascii\n        $s4 = \"https://www.bing.com/bufio:\" ascii\n        $s5 = \"http://crypto/tls:\" ascii\n        $s6 = \"http://Mozilla/5.0\" ascii\n    condition:\n        uint32(0) == 0x464c457f and\n        filesize >= 3499732 and filesize <= 9334668 and\n        2 of ($s*)\n}"
    },
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
