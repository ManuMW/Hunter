# 0002 Air-Gapped Sandbox Network

## Status
Accepted

## Context and Decision
Malware detonating in a cloud environment frequently attempts to connect to external Command and Control (C2) servers, participate in distributed denial of service (DDoS), or scan external IP addresses. Outbound malicious traffic from a Google Cloud Platform (GCP) instance will trigger automated abuse detection, leading to billing account and project suspension.

We decided to execute all Detonation Sandboxes with complete network isolation using Docker's `--network none` flag, foregoing complex network simulation tools like INetSim for the initial phase.

## Consequences
- Guaranteed zero outbound traffic from the sandbox, eliminating any risk of GCP abuse penalties or IP blacklisting.
- Zero network setup overhead (no proxy, no custom DNS routing, no secondary simulation container).
- Samples requiring external network connectivity (e.g., secondary payload downloaders, C2 check-in bots) will fail or exit prematurely.
- Analysis is strictly limited to local host behavior (process spawning, file modifications, persistence hooks, and static extraction).
