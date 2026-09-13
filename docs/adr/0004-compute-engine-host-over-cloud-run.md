# 0004 Compute Engine Host Over Cloud Run for Sandbox Isolation

## Status
Accepted

## Context and Decision
We considered running the orchestration service on Google Cloud Run (a fully managed serverless container service) to eliminate virtual machine management.

However, Cloud Run executes containers inside Google's managed gVisor sandbox and does not support running the Docker daemon (`dockerd`), Docker-in-Docker, or spawning child sibling containers. If malware were executed directly inside a Cloud Run instance, it would share the container environment with the API service and its sensitive credentials (e.g., Google AI Studio API keys, GitHub tokens), creating a major credential theft risk. Furthermore, per-container runtime network isolation (`--network none`) is unsupported on Cloud Run.

We decided to host the pipeline on a dedicated GCP Compute Engine VM (e2-micro / e2-small). The VM acts as the Detonation Host, allowing Docker to spawn isolated, ephemeral child sandboxes with dropped network interfaces, strict resource quotas, and full credential isolation from the host.

## Consequences
- Requires provisioning and managing a Linux VM in GCP (eligible for GCP Free Tier `e2-micro`).
- Guarantees strict boundary isolation: malware executes inside ephemeral Docker containers without access to the host VM's filesystem or environment variables/API keys.
- Supports offline (`--network none`) execution per container instance.
