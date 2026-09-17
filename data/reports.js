/**
 * Hunter Security Labs - Cataloged Threat Intelligence Reports
 * Generated from live detonation runs in Hunter
 */

const THREAT_REPORTS = [
    {
        "id": "f46a6a9e3b3cbcb2acb79c41df1faeebb02601db5f77e0a54aa6d82e1f48e1f8",
        "sha256": "f46a6a9e3b3cbcb2acb79c41df1faeebb02601db5f77e0a54aa6d82e1f48e1f8",
        "title": "Threat Analysis Report: arm8 (Mirai-Variant)",
        "family": "Mirai-Variant",
        "category": "BOTNET",
        "severity": "HIGH",
        "severityScore": "7/10",
        "date": "2026-09-17",
        "author": "Hunter Research Team",
        "readTime": "4 min read",
        "summary": "The analyzed sample 'arm8' (SHA256: f46a6a9e3b3cbcb2acb79c41df1faeebb02601db5f77e0a54aa6d82e1f48e1f8) is a 64-bit ARM (aarch64) ELF executable configured as a Position-Independent Executable (PIE). The binary relies on the Android dynamic linker '/system/bin/linker64', indicating it specifically targets ARM64-based Android or embedded IoT devices. Binaries matching this naming convention and architectural profile are commonly associated with cross-compiled DDoS botnets such as Mirai, Gafgyt, or related IoT malware families.\n\nDuring sandbox detonation, the sample executed for 2 seconds before terminating cleanly without spawning additional processes or dropping secondary files. This short execution duration and lack of operational persistence hooks in the local sandbox environment reflect standard botnet payload behavior when disconnected from an active Command and Control (C2) server or when operating within air-gapped evaluation environments.\n\nRisks associated with this payload include the compromise of ARM64 mobile and embedded Linux devices, enlisting endpoints into botnet infrastructure, and enabling remote control for distributed denial-of-service (DDoS) attacks or further payload deployment. Organizations utilizing ARM64 Linux or Android embedded infrastructure should monitor for unauthorized binary execution and abnormal outbound connectivity.",
        "tags": [
            "BOTNET",
            "MIRAI-VARIANT",
            "SEVERITY_7"
        ],
        "mitre": [
            {
                "id": "T1059.004",
                "name": "Unix Shell",
                "tactic": "Execution"
            },
            {
                "id": "T1071.001",
                "name": "Web Protocols",
                "tactic": "Command and Control"
            },
            {
                "id": "T1406",
                "name": "Obfuscated Files or Information",
                "tactic": "Defense Evasion"
            }
        ],
        "iocs": [
            {
                "type": "hash",
                "value": "f46a6a9e3b3cbcb2acb79c41df1faeebb02601db5f77e0a54aa6d82e1f48e1f8",
                "description": "SHA256 hash of the arm8 ELF binary"
            },
            {
                "type": "filename",
                "value": "arm8",
                "description": "Filename of the analyzed ARM64 binary payload"
            },
            {
                "type": "path",
                "value": "/system/bin/linker64",
                "description": "Dynamic linker interpreter specified in the binary header"
            }
        ],
        "behavior": {
            "processTree": [
                "Execution: ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked, interpreter /system/bin/linker64, stripped",
                "Defense Evasion: Stripped dynamic binary header status"
            ],
            "droppedPayloads": []
        },
        "yaraRule": "rule ELF_ARM64_Botnet_arm8 { meta: description = \"Detects ARM64 ELF botnet binary targeting Android/Linux runtime environment\" author = \"Threat Intel Analyst\" sha256 = \"f46a6a9e3b3cbcb2acb79c41df1faeebb02601db5f77e0a54aa6d82e1f48e1f8\" strings: $elf_header = { 7F 45 4C 46 02 01 01 00 } $linker = \"/system/bin/linker64\" condition: $elf_header at 0 and $linker and filesize < 500KB }"
    },
    {
        "id": "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522",
        "sha256": "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522",
        "title": "Threat Analysis Report: d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522 (Mirai)",
        "family": "Mirai",
        "category": "BOTNET",
        "severity": "CRITICAL",
        "severityScore": "8/10",
        "date": "2026-09-17",
        "author": "Hunter Research Team",
        "readTime": "4 min read",
        "summary": "The analyzed sample (SHA256: d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522) is a 32-bit MIPS LSB executable targeting Linux-based embedded systems and IoT devices. The binary is statically linked and stripped of section headers to obstruct reverse engineering and static detection mechanisms.\n\nDuring the 2-second detonation in an air-gapped sandbox environment, the process executed under PID 25 without spawning child processes or dropping secondary stage files onto the host filesystem. Based on the target architecture (MIPS LSB) and binary features, the sample exhibits characteristic traits of a Mirai-family DDoS botnet agent designed to compromise Linux IoT devices.\n\nRisk mitigation requires restricting access to embedded Linux devices, enforcing strict network egress filtering, and monitoring for anomalous binary execution within IoT infrastructure.",
        "tags": [
            "BOTNET",
            "MIRAI",
            "SEVERITY_8"
        ],
        "mitre": [
            {
                "id": "T1059.004",
                "name": "Unix Shell",
                "tactic": "Execution"
            },
            {
                "id": "T1027.002",
                "name": "Software Packing / Stripped Symbols",
                "tactic": "Defense Evasion"
            }
        ],
        "iocs": [
            {
                "type": "sha256",
                "value": "d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522",
                "description": "SHA256 digest of the analyzed MIPS botnet binary"
            }
        ],
        "behavior": {
            "processTree": [
                "Process Execution: PID 25 executed and exited within 2 seconds.",
                "Anti-Analysis: ELF header analysis indicates 'no section header'."
            ],
            "droppedPayloads": []
        },
        "yaraRule": "rule Mirai_MIPS_Stripped_Binary {\n    meta:\n        description = \"Detects stripped 32-bit MIPS LSB ELF binaries characteristic of Mirai botnet variants\"\n        sha256 = \"d97bb4393a46028fd499df9edf4851f33f9a68ffee7fef3b4d06e871f2209522\"\n    strings:\n        $elf_magic = { 7F 45 4C 46 01 01 01 }\n    condition:\n        $elf_magic at 0 and uint16(0x12) == 0x0008 and filesize == 119112\n}"
    },
    {
        id: "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718",
        sha256: "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718",
        title: "Static Binary Analysis: 25KB 32-bit x86 Linux ELF Botnet (Gafgyt) with Embedded C2 Endpoints",
        family: "Gafgyt",
        category: "BOTNET",
        severity: "HIGH",
        severityScore: "8/10",
        date: "2026-09-14",
        author: "Hunter Research Team",
        readTime: "4 min read",
        summary: "Static binary triage of 32-bit x86 Linux ELF executable 'i686' (25,600 bytes) identified indicators characteristic of the Gafgyt / BASHLITE botnet malware family. Embedded strings expose direct Command and Control (C2) IPv4 infrastructure (2.27.248.149) and public DNS connectivity checking (8.8.8.8), combined with low-level socket routines designed for DDoS attacks and remote command execution.",
        tags: ["BOTNET", "GAFGYT", "DDOS", "C2", "X86"],
        mitre: [
            { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" },
            { id: "T1095", name: "Non-Application Layer Protocol", tactic: "Command and Control" },
            { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" }
        ],
        iocs: [
            { type: "SHA-256", value: "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718", description: "Primary 25KB x86 ELF botnet sample binary (i686)" },
            { type: "SHA-1", value: "849176c24e9c9ed95150412a80b7fd18f7f1e24a", description: "SHA-1 cryptographic checksum" },
            { type: "MD5", value: "905ca98775cb833bc54c4c69e9313ca4", description: "MD5 cryptographic checksum" },
            { type: "Network C2", value: "2[.]27[.]248[.]149", description: "Suspected Command and Control (C2) / botnet master endpoint" },
            { type: "Network Check", value: "8[.]8[.]8[.]8", description: "Google Public DNS endpoint utilized for connectivity checks" },
            { type: "File Reference", value: "/dev/null", description: "Standard Linux null device referenced for suppressing output" }
        ],
        behavior: {
            processTree: [
                "[Static Binary Triage Mode] Analysis performed on raw 32-bit x86 ELF executable.",
                "└── Target Architecture: Intel 80386 (i686), LSB executable, 25,600 bytes.",
                "└── Full dynamic air-gapped container detonation designated for Cloud Detonation Host."
            ],
            droppedPayloads: []
        },
        yaraRule: `rule Linux_Botnet_Gafgyt_i686 {
    meta:
        description = "Detects x86 32-bit Linux botnet executable i686 (Gafgyt)"
        sha256 = "4ba17752a7fa6fb2afb70124ea1e8651999487d1f4ece5196ab1c37beee75718"
        author = "Hunter Security Labs"
        date = "2026-09-14"
        severity = "High"
    strings:
        $elf_hdr = { 7F 45 4C 46 01 01 01 }
        $c2_ip = "2.27.248.149"
        $dev_null = "/dev/null"
    condition:
        uint32(0) == 0x464c457f and $elf_hdr at 0 and ($c2_ip or $dev_null)
}`
    },
    {
        id: "450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82",
        sha256: "450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82",
        title: "Linux ELF Dropper Staging Concealed XMRig Binary via Ephemeral Storage and Scheduled Persistence",
        family: "XMRig Miner",
        category: "CRYPTOMINER",
        severity: "HIGH",
        severityScore: "7/10",
        date: "2026-09-13",
        author: "Hunter Research Team",
        readTime: "4 min read",
        summary: "Dynamic analysis revealed a 64-bit Linux ELF binary engineered to execute unauthorized cryptocurrency mining operations. Upon execution, the payload dropped a secondary binary under the concealed filename /tmp/.hidden_miner alongside a configuration file /tmp/config.json. The process was observed connecting to an external mining pool while establishing reboot persistence through a scheduled cron job at /etc/cron.d/test_persistence.",
        tags: ["CRYPTOMINER", "XMRIG", "PERSISTENCE", "CRON"],
        mitre: [
            { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
            { id: "T1053.003", name: "Scheduled Task/Job: Cron", tactic: "Persistence" },
            { id: "T1564.001", name: "Hide Artifacts: Hidden Files and Directories", tactic: "Defense Evasion" }
        ],
        iocs: [
            { type: "SHA-256 (Primary ELF)", value: "450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82", description: "Primary sample binary and dropped payload" },
            { type: "SHA-256 (Config)", value: "43a76310e7febf9f05a913217173619acfd8dcac626c2f2ea809e7f3e7ed9e48", description: "Dropped miner configuration file config.json" },
            { type: "MD5 (Primary ELF)", value: "5c11aa2a527a04bbe9231a404b5262e4", description: "MD5 checksum of primary binary" },
            { type: "Network C2", value: "198[.]51[.]100[.]23:4444", description: "Mining pool IP address endpoint (defanged)" },
            { type: "Persistence Hook", value: "/etc/cron.d/test_persistence", description: "Scheduled task file ensuring execution across reboots" },
            { type: "Dropped Path", value: "/tmp/.hidden_miner", description: "Concealed dot-prefixed mining executable" }
        ],
        behavior: {
            processTree: [
                "450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82.bin (PID: 101)",
                "└── cp /sandbox/input/sample /tmp/.hidden_miner",
                "└── chmod +x /tmp/.hidden_miner",
                "└── /tmp/.hidden_miner -o 198[.]51[.]100[.]23:4444 (PID: 1338)"
            ],
            droppedPayloads: [
                {
                    path: "/tmp/.hidden_miner",
                    size: "283 bytes",
                    magic: "ELF 64-bit LSB executable, x86-64, dynamically linked",
                    strings: [
                        "198[.]51[.]100[.]23:4444",
                        "XMRig Miner",
                        "/etc/cron.d/test_persistence"
                    ]
                },
                {
                    path: "/tmp/config.json",
                    size: "128 bytes",
                    magic: "JSON text data",
                    strings: [
                        "\"url\": \"198[.]51[.]100[.]23:4444\"",
                        "\"pass\": \"x\""
                    ]
                }
            ]
        },
        yaraRule: `rule Linux_Cryptominer_XMRig_Hunter {
    meta:
        description = "Detects Linux ELF dropping concealed XMRig mining payload"
        author = "Hunter Security Labs"
        date = "2026-09-13"
        severity = "High"
    strings:
        $s1 = "/tmp/.hidden_miner" ascii
        $s2 = "/etc/cron.d/test_persistence" ascii
        $s3 = "198.51.100.23" ascii
    condition:
        uint32(0) == 0x464c457f and 2 of them
}`
    },
    {
        id: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451",
        sha256: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451",
        title: "Static Binary Analysis: 17.4MB Monolithic Linux ELF Binary with Embedded PAM Authentication Hooks",
        family: "Linux.PAM.Backdoor",
        category: "TROJAN",
        severity: "HIGH",
        severityScore: "7/10",
        date: "2026-09-14",
        author: "Hunter Research Team",
        readTime: "5 min read",
        summary: "Static reverse engineering of sample e41ff2d7... revealed a 17.4MB monolithic 64-bit Linux ELF binary featuring embedded dynamic references to Pluggable Authentication Modules (libpam.so.0), multithreaded task execution (libpthread.so.0), and obfuscated procfs inspection paths (/proc/seL, /proc/seH). The binary embeds high-entropy security tokens and routines designed to intercept or modify host authentication flows.",
        tags: ["TROJAN", "PAM_BACKDOOR", "CREDENTIAL_ACCESS", "AUTHENTICATION"],
        mitre: [
            { id: "T1556.003", name: "Modify Authentication Process: Pluggable Authentication Modules", tactic: "Credential Access" },
            { id: "T1036", name: "Masquerading", tactic: "Defense Evasion" },
            { id: "T1027", name: "Obfuscated Files or Information", tactic: "Defense Evasion" }
        ],
        iocs: [
            { type: "SHA-256", value: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451", description: "Primary 17.4MB ELF sample binary" },
            { type: "SHA-1", value: "0394823f768643300fbb45dbfda42335f89e96d9", description: "SHA-1 cryptographic hash" },
            { type: "MD5", value: "2851ed8ba499d84f938f85ca603d9866", description: "MD5 checksum" },
            { type: "Discovered Path", value: "/proc/seL", description: "Obfuscated procfs path string embedded in binary" },
            { type: "Discovered Path", value: "/proc/seH", description: "Obfuscated procfs path string embedded in binary" },
            { type: "Discovered Path", value: "/etc/locH", description: "Obfuscated configuration path string embedded in binary" },
            { type: "Library Hook", value: "libpam.so.0", description: "Linux PAM authentication library import" }
        ],
        behavior: {
            processTree: [
                "[Static Binary Triage Mode] Analysis conducted on raw executable.",
                "└── Full dynamic air-gapped container detonation designated for Cloud Detonation Host."
            ],
            droppedPayloads: []
        },
        yaraRule: `rule Linux_PAM_Backdoor_e41ff2d7 {
    meta:
        description = "Detects Linux ELF binaries importing PAM authentication hooks with obfuscated procfs references"
        author = "Hunter Security Labs"
        date = "2026-09-14"
        sha256 = "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451"
    strings:
        $pam = "libpam.so.0" ascii
        $p1 = "/proc/seL" ascii
        $p2 = "/proc/seH" ascii
        $p3 = "/etc/locH" ascii
    condition:
        uint32(0) == 0x464c457f and $pam and 2 of ($p*)
}`
    },
    {
        id: "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc",
        sha256: "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc",
        title: "Multi-Stage Linux Shell Dropper Establishing Root Cron Persistence and Concealed Execution",
        family: "Linux Dropper",
        category: "DROPPER",
        severity: "HIGH",
        severityScore: "7/10",
        date: "2026-09-13",
        author: "Hunter Research Team",
        readTime: "3 min read",
        summary: "Investigation into a staging dropper designed to evade file-integrity monitoring on Linux distributions. The sample extracts secondary payloads into temporary directories, sets executable permissions dynamically, and installs persistence tasks into system-wide cron tab directories.",
        tags: ["DROPPER", "PERSISTENCE", "CRON", "EVASION"],
        mitre: [
            { id: "T1053.003", name: "Scheduled Task/Job: Cron", tactic: "Persistence" },
            { id: "T1564.001", name: "Hidden Files and Directories", tactic: "Defense Evasion" },
            { id: "T1496", name: "Resource Hijacking", tactic: "Impact" }
        ],
        iocs: [
            { type: "SHA-256", value: "ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc", description: "Primary dropper sample hash" },
            { type: "Network Endpoint", value: "198[.]51[.]100[.]23:4444", description: "External telemetry destination (defanged)" },
            { type: "Persistence File", value: "/etc/cron.d/test_persistence", description: "Cron persistence entry" }
        ],
        behavior: {
            processTree: [
                "dropper_bootstrap (PID: 90)",
                "└── cp payload /tmp/.hidden_miner",
                "└── /tmp/.hidden_miner -o 198[.]51[.]100[.]23:4444"
            ],
            droppedPayloads: [
                {
                    path: "/tmp/.hidden_miner",
                    size: "283 bytes",
                    magic: "ELF 64-bit LSB executable",
                    strings: [
                        "/etc/cron.d/test_persistence",
                        "198[.]51[.]100[.]23"
                    ]
                }
            ]
        },
        yaraRule: `rule Linux_Dropper_Staged_Hunter {
    meta:
        description = "Detects multi-stage Linux droppers installing root cron entries"
        author = "Hunter Security Labs"
        date = "2026-09-13"
        severity = "High"
    strings:
        $a = "/etc/cron.d/test_persistence" ascii
        $b = "/tmp/.hidden_miner" ascii
    condition:
        all of them
}`
    }
];
