# 0007 Dropped Payload Decomposition and Quarantine Chaining

## Status
Accepted

## Context and Decision
Real-world malware droppers frequently extract and execute secondary stages (such as mining daemons, ransomware encryptors, or persistence scripts) in temporary directories like `/tmp`, `/var/tmp`, or `/dev/shm`. Analyzing only the initial parent binary fails to capture the true operational payload.

We decided to implement:
1. **Automated Payload Extraction & Static Decomposition**: The triage pipeline copies dropped files out of the sandbox, computes their SHA-256 hashes, classifies their MIME/magic types, and extracts embedded strings, URLs, and configurations.
2. **In-Report Attack-Chain Synthesis**: Google AI Studio Gemini analyzes the relationship between the primary dropper and its dropped payloads, documenting the multi-stage attack lifecycle in the Threat Analysis Report.
3. **Quarantine Chaining**: Dropped executable binaries are automatically registered into the Quarantine Store under their SHA-256 hash (`chmod 0600`), allowing analysts to queue an independent Detonation Run on any dropped sub-payload.

## Consequences
- Produces comprehensive multi-stage threat intelligence within a single execution cycle.
- Automatically captures and quarantines secondary payloads for standalone analysis.
- Increases triage processing slightly to extract strings and parse dropped binaries.
