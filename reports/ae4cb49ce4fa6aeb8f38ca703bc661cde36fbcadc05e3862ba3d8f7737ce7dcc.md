---
title: Threat Analysis Report - test_sample.sh
date: 2026-09-13 12:57:41 UTC
sha256: ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc
severity_score: 8
malware_family: "Generic Monero Cryptominer"
classification: "Cryptominer"
tags:
  - Cryptominer
  - Severity_8
---

# Threat Analysis Report: `test_sample.sh`

> **Analysis Timestamp**: 2026-09-13 12:57:41 UTC  
> **Threat Classification**: `Cryptominer`  
> **Severity Score**: **8/10**  
> **Suspected Family**: `Generic Monero Cryptominer`  
> **Confidence**: `95%`

## 1. Executive Summary

The analyzed sample, test_sample.sh, is a malicious Linux shell script designed to deploy and execute a cryptocurrency mining payload on targeted systems. Upon execution under root privileges, the dropper script extracts and places a hidden ELF binary binary into /tmp/.hidden_miner along with a JSON configuration file specifying mining pool parameters and wallet credentials. The miner process is immediately spawned to connect to an external mining pool host at 198.51.100.23 on port 4444. Furthermore, the malware attempts to establish persistence across reboots by dropping a scheduled cron job configuration into /etc/cron.d/test_persistence. This activity results in unauthorized consumption of system computing resources, potential degradation of service, and persistence within administrative contexts.

## 2. Sample File Details

| Attribute | Value |
| :--- | :--- |
| **Original Filename** | `test_sample.sh` |
| **File Type** | `Shell Script` |
| **File Size** | `783 bytes` |
| **SHA-256** | `ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc` |
| **SHA-1** | `8bf7fcd9722477cda7960e480bb7ae31e1967f34` |
| **MD5** | `3423f027455e110aeb98620fe0022bc5` |

## 3. MITRE ATT&CK Mapping

| Technique ID | Technique Name | Tactic | Observed Forensic Evidence |
| :--- | :--- | :--- | :--- |
| [`T1496`](https://attack.mitre.org/techniques/T1496) | Resource Hijacking | `Impact` | Execution of /tmp/.hidden_miner process targeting mining pool 198[.]51[.]100[.]23:4444 to mine cryptocurrency using CPU resources. |
| [`T1053.003`](https://attack.mitre.org/techniques/T1053/003) | Scheduled Task/Job: Cron | `Persistence` | Creation of persistent cron task file at /etc/cron.d/test_persistence. |
| [`T1564.001`](https://attack.mitre.org/techniques/T1564/001) | Hide Artifacts: Hidden Files and Directories | `Defense Evasion` | Staging executable as a hidden binary at /tmp/.hidden_miner. |
| [`T1059.004`](https://attack.mitre.org/techniques/T1059/004) | Command and Scripting Interpreter: Unix Shell | `Execution` | Initial deployment executed via shell script test_sample.sh. |

## 4. Observed Dynamic Behaviors

| Category | Description | Evidence |
| :--- | :--- | :--- |
| `Execution` | Execution of initial dropper shell script creating subprocesses | `Detonation of test_sample.sh (PID 1337)` |
| `Defense Evasion` | Dropping hidden executable payload in temporary folder | `File creation at path /tmp/.hidden_miner` |
| `Persistence` | Scheduled job creation for automated re-execution | `File permissions and path /etc/cron.d/test_persistence` |
| `Impact` | Execution of background cryptocurrency mining payload | `Process command line '\_ /tmp/.hidden_miner -o 198[.]51[.]100[.]23:4444'` |

## 5. Indicators of Compromise (IoCs)

| Type | Defanged Value | Description |
| :--- | :--- | :--- |
| `sha256` | `ae4cb49ce4fa6aeb8f38ca703bc661cde36fbcadc05e3862ba3d8f7737ce7dcc` | SHA256 hash of installer shell script test_sample.sh |
| `sha256` | `450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82` | SHA256 hash of dropped hidden miner binary .hidden_miner |
| `sha256` | `43a76310e7febf9f05a913217173619acfd8dcac626c2f2ea809e7f3e7ed9e48` | SHA256 hash of dropped miner configuration config.json |
| `ip` | `198[.]51[.]100[.]23` | Destination IP address of cryptocurrency mining pool |
| `wallet_address` | `48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ` | Monero cryptocurrency wallet address used by attacker |
| `filepath` | `/tmp/.hidden_miner` | Path to dropped miner executable |
| `filepath` | `/etc/cron.d/test_persistence` | Path to cron persistence configuration file |

## 6. Dropped Payloads & Multi-Stage Attack Decomposition

> [!NOTE]
> All executable sub-payloads staged during execution have been quarantined on the Detonation Host and are available for standalone detonation.

| Dropped File | Operational Role | File Type | SHA-256 | Quarantine Status |
| :--- | :--- | :--- | :--- | :--- |
| `.hidden_miner` | `Cryptominer Payload Engine` | `Linux ELF Binary` | `450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82` | `Quarantined (Detonatable)` |
| `config.json` | `Miner Configuration File` | `JSON Data File` | `43a76310e7febf9f05a913217173619acfd8dcac626c2f2ea809e7f3e7ed9e48` | `Quarantined (Detonatable)` |

### Sub-Payload Analysis Deep-Dive

#### Target: `.hidden_miner` (Cryptominer Payload Engine)
- **SHA-256**: `450adfde6d2cad6d7f7d987c007d5a3d02bc5ea78de0640f65d42cd47dec2f82`
- **File Type**: `Linux ELF Binary`
- **Behavioral Role**: Compiled 64-bit Linux executable designed to execute Monero hashing routines and communicate with configured remote mining pool infrastructure.
- **Extracted Indicators / Configs**: `198[.]51[.]100[.]23:4444`, `48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ`

#### Target: `config.json` (Miner Configuration File)
- **SHA-256**: `43a76310e7febf9f05a913217173619acfd8dcac626c2f2ea809e7f3e7ed9e48`
- **File Type**: `JSON Data File`
- **Behavioral Role**: JSON formatted config file storing connection details, destination wallet address, and password for pool connection.
- **Extracted Indicators / Configs**: `198[.]51[.]100[.]23:4444`, `48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ`


## 7. Detailed Sandbox Forensic Triage

### Spawned Process Tree
```text
PID 1338 (User: root): \_ /tmp/.hidden_miner -o 198[.]51[.]100[.]23:4444
```

### Staged & Dropped Files
```text
-rwxr-xr-x 2048 /tmp/.hidden_miner
-rw-r--r-- 128 /tmp/config.json
```

### Persistence Hooks (Cron/Systemd)
```text
-rw-r--r-- 1 root root 45 Sep 13 14:01 /etc/cron.d/test_persistence
```

## 8. YARA Detection Rule

```yara
rule Linux_Cryptominer_HiddenMiner { meta: description = "Detects Linux hidden miner payload and configuration artifacts" author = "Threat Intel Analyst" date = "2024-09-13" strings: $s1 = "48edfHu7V9Z84YzzMa6fUUEoXZ83BHM7YG51jRtPZ" ascii $s2 = "198.51.100.23:4444" ascii $path = "/tmp/.hidden_miner" ascii $elf = { 7F 45 4C 46 } condition: ($elf at 0 and any of ($s1, $s2)) or ($path) }
```

---
*Report automatically generated by Threat Research Pipeline.*