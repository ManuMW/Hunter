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

## Core Invariant: Jira Task Lifecycle & Gated Execution
1. **Mandatory Jira Intake**:
   - For every task, feature, or bug fix requested by the user, the assistant must first consult Jira (Project `HUN`).
   - Never begin implementation or modify codebase files before performing the Jira intake workflow.

2. **Collision & Deduplication Check**:
   - Search existing issues using JQL text search (`project = HUN AND (summary ~ "..." OR description ~ "...")`) to check if the problem or task already has an open or closed ticket.
   - If an existing or colliding ticket is identified, flag the relationship, link the issue, and inform the user.

3. **Autonomous Ticket Creation**:
   - If no matching ticket exists, create a new issue in project `HUN` (`Task` or `Bug`) with clear summary, detailed description, and relevant labels.

4. **Strict User Authorization Gate**:
   - After identifying or creating the ticket, the assistant must pause and present the ticket ID, summary, and scope to the user.
   - The assistant must NOT begin building, editing files, or running build commands until the user explicitly confirms (e.g., "work on it", "proceed", "build this").

5. **Execution & Traceability**:
   - Once authorized, perform the work and reference the Jira issue key (e.g., `HUN-XX`) in commit messages and summaries.
