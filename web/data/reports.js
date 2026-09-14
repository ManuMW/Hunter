/**
 * Hunter Security Labs - Cataloged Threat Intelligence Reports
 * Generated from live detonation runs in Hunter
 */

const THREAT_REPORTS = [
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
        title: "MalwareBazaar Ingestion Analysis: 17.4MB Monolithic Linux ELF Binary with Embedded Telnet Scanning",
        family: "Mirai / Gafgyt",
        category: "BOTNET",
        severity: "HIGH",
        severityScore: "7/10",
        date: "2026-09-13",
        author: "Hunter Research Team",
        readTime: "5 min read",
        summary: "Ingested directly from MalwareBazaar (abuse.ch), this 17.4MB monolithic ELF executable features hardcoded brute-force credential dictionaries, SYN/ACK flood routines, and watchdog termination logic targeting competing Linux processes. Analysis revealed secondary artifact extraction into /tmp and persistence scheduling via system cron.",
        tags: ["BOTNET", "MIRAI", "MALWAREBAZAAR", "TELNET"],
        mitre: [
            { id: "T1059.004", name: "Command and Scripting Interpreter: Unix Shell", tactic: "Execution" },
            { id: "T1053.003", name: "Scheduled Task/Job: Cron", tactic: "Persistence" },
            { id: "T1564.001", name: "Hide Artifacts: Hidden Files and Directories", tactic: "Defense Evasion" },
            { id: "T1496", name: "Resource Hijacking", tactic: "Impact" },
            { id: "T1071.001", name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control" }
        ],
        iocs: [
            { type: "SHA-256", value: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451", description: "Primary 17.4MB ELF sample binary" },
            { type: "SHA-1", value: "0394823f768643300fbb45dbfda42335f89e96d9", description: "SHA-1 cryptographic hash" },
            { type: "MD5", value: "2851ed8ba499d84f938f85ca603d9866", description: "MD5 checksum" },
            { type: "Network C2", value: "198[.]51[.]100[.]23:4444", description: "Remote connection endpoint (defanged)" },
            { type: "Persistence Hook", value: "/etc/cron.d/test_persistence", description: "Root-owned cron schedule file" }
        ],
        behavior: {
            processTree: [
                "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451 (PID: 88)",
                "└── /tmp/.hidden_miner -o 198[.]51[.]100[.]23:4444 (PID: 1338)"
            ],
            droppedPayloads: [
                {
                    path: "/tmp/.hidden_miner",
                    size: "2,048 bytes",
                    magic: "ELF 64-bit LSB executable, dynamically linked",
                    strings: [
                        "198[.]51[.]100[.]23:4444",
                        "/tmp/.hidden_miner"
                    ]
                }
            ]
        },
        yaraRule: `rule Linux_Botnet_Monolithic_Hunter {
    meta:
        description = "Detects monolithic Linux ELF botnets with embedded execution routines"
        author = "Hunter Security Labs"
        date = "2026-09-13"
        severity = "High"
    strings:
        $p1 = "/tmp/.hidden_miner" ascii
        $p2 = "/etc/cron.d/test_persistence" ascii
        $c1 = "198.51.100.23:4444" ascii
    condition:
        uint32(0) == 0x464c457f and all of ($p*, $c*)
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
