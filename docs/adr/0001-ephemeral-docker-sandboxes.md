# 0001 Ephemeral Docker Sandboxes for Sample Detonation

## Status
Accepted

## Context and Decision
We need an execution environment to detonate untrusted malware samples. Standard practice in threat analysis is to use full hypervisor virtualization (KVM, QEMU, Firecracker) to prevent kernel exploitation and escapes. However, dedicated virtualization instances on GCP require nested virtualization support and higher-tier instance sizes, incurring significant infrastructure costs.

We decided to use on-demand, ephemeral Docker containers running on a standard Linux VM for sample detonation. Each container is spun up per sample, executes under restricted resource limits, and is immediately destroyed after artifact extraction.

## Consequences
- Significantly lowers GCP VM hosting costs by running on small standard compute instances without nested virtualization.
- Accepts shared Linux kernel risk; kernel-level exploits (e.g., Dirty COW, namespace escapes) could compromise the host instance.
- Requires defense-in-depth container hardening (dropping Linux capabilities, non-privileged flags, and isolated internal bridge networking) to mitigate host compromise and GCP abuse penalties.
