# 0003 Standalone Velociraptor CLI for Offline Triage

## Status
Accepted

## Context and Decision
We need to collect forensic evidence (process trees, crontabs, file modifications) from the air-gapped Detonation Sandbox (`--network none`). Velociraptor can operate as a client-server daemon or as a standalone CLI artifact collector.

We decided to bake the standalone `velociraptor` binary directly into the sandbox Docker image. When the execution timeout expires, a container orchestrator script invokes `velociraptor artifacts collect` locally, writing a self-contained ZIP archive to a mounted host directory before container destruction.

## Consequences
- No persistent Velociraptor server infrastructure or database is required on the host.
- Operates reliably inside an air-gapped container with zero network dependencies.
- Artifact collection profiles are baked into the container image or provided via configuration file at spin-up time.
