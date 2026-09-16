# Hunter Threat Research - Workspace Guidelines & Invariants

## Core Invariant: Cloud-Only Architecture
1. **Zero Local Detonation**:
   - Dynamic malware detonation, container sandboxing, and live binary triage must NEVER be executed on the local developer machine.
   - The user's workstation is strictly for code authoring, testing, and repository management.
   - Never instruct the user to run local dynamic analysis or CLI detonation (`python -m src.cli analyze <hash>`) on their personal machine for sample triage.

2. **GCP Cloud Detonation Host as Sole Execution Target**:
   - All sample ingestion from MalwareBazaar, decryption, quarantine storage, air-gapped Docker execution, and Velociraptor forensic triage run exclusively on the Cloud Detonation Host (GCP Compute Engine).
   - Production API services run as systemd services on the cloud VM (`deploy/hunter-detonation.service`).

3. **Client-Facing UI Abstraction**:
   - The public Report Hub (GitHub Pages) is strictly an intelligence consumption and hash submission portal inspired by Elastic Security Labs.
   - Never expose backend internals, VM hostnames, cloud provider references ("Option B", "GCP Compute Host"), or internal CLI/shell commands to end-users or clients.
   - Uncataloged or queued samples must display clean, customer-facing statuses (e.g., "Sample Submitted", "Analysis Queued") without exposing backend plumbing or diagnostic debug instructions.

4. **Zero Synthetic / Fake Telemetry**:
   - Never generate or inject hardcoded mock IOCs, fake process trees, or synthetic forensic dumps.
   - Analysis must always be derived from genuine static decomposition or genuine dynamic container telemetry.
