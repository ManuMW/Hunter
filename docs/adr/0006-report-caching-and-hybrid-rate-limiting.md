# 0006 Report Caching and Hybrid Rate Limiting

## Status
Accepted

## Context and Decision
A public threat analysis service must prevent redundant work (e.g., re-running a 90-second detonation on the same popular hash) and prevent single users or bots from exhausting GCP host resources or Gemini API quotas.

We decided to implement:
1. **Report Caching & In-Flight Deduplication**: If `reports/<sha256>.md` exists, the system returns the cached report immediately (0s latency, 0 compute, no quota consumed). If a hash is currently detonating in the queue, subsequent requests join the active task.
2. **Hybrid Rate Limiting**: Combines Cloudflare Turnstile bot verification on the frontend with backend IP and browser UUID tracking persisted in a local SQLite database, enforcing a strict cap of 5 fresh sample detonations per client per calendar day (UTC).

## Consequences
- Protects the GCP host from queue bloat and redundant executions.
- Guarantees immediate response for previously analyzed hashes.
- Enforces fair usage without requiring user account registration or login friction.
