# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

## Reporting a vulnerability

Please use GitHub's **private vulnerability reporting** (repository **Security** tab, then
**Report a vulnerability**). Do not open public issues for security problems. Include the
component (agent, server, dashboard), version, OS, and a minimal reproduction using synthetic
data only.

Expect an acknowledgement within 5 business days and an initial assessment within 10. Please
allow reasonable time for a fix before disclosure; credit is given if you want it.

## Scope

In scope: crafted telemetry, rules, configs or API requests that cause code execution, memory
corruption, authentication bypass, data written outside intended paths, token disclosure,
denial of service out of proportion to input size, or misleading results (for example an
incident whose evidence does not belong to it).

Out of scope: detections that miss an attack technique (open a normal issue or PR for rule
improvements), and already-public issues in third-party dependencies.

## Security design

**Agent (C++)**
- Monitor-only: reads the Sysmon event log channel and ETW providers that Windows already
  exposes. It never blocks, kills, suspends or injects into processes, never touches LSASS
  (the `lsass-access` rule only *reads* Sysmon event 10 records), never hides or persists
  itself, and never changes system, Sysmon or ETW configuration. If an ETW session with its
  name already exists it reports the conflict rather than stopping it.
- Untrusted input is parsed defensively: the XML reader rejects DOCTYPE / entity declarations
  (no XXE, no entity expansion) and caps size and depth; JSON and YAML parsers cap depth;
  replay lines are capped at 1 MiB; `-EncodedCommand` payloads at 64 KiB; regex subjects at
  4 KiB. Enrichment fields cannot be supplied by input.
- The enrollment token is read from an environment variable named in the config (never stored
  in the config file), is not logged, and is wiped from memory by the WinHTTP transport.
- HTTPS certificate validation is always on (WinHTTP default trust store); plain `http://` is
  accepted only for `127.0.0.1`, `localhost` and `[::1]`. The spool file is created `0600`
  with `O_NOFOLLOW` on POSIX.

**Server (Python)**
- Agents authenticate with `Authorization: Bearer <token>` plus `X-Agent-Id`. Only SHA-256
  digests of tokens are configured (`EDR_AGENT_TOKEN_HASHES`), compared with
  `hmac.compare_digest`, with the same work done for unknown agent ids.
- Request bodies are capped (default 2 MiB, enforced while reading, chunked bodies included),
  batches are capped (default 1000 items), each agent is rate limited (default 120 requests per
  minute), and every event is validated by the same checks the engine uses.
- Ingest is idempotent (event ids are unique; incident versions only move forward). The server
  re-scores stored telemetry itself and flags any agent/server score disagreement instead of
  trusting the agent's numbers.
- Binds to `127.0.0.1` by default; the read API can require a token (`EDR_READ_TOKEN_HASH`).
  No secrets are logged; logs carry agent ids and counts.

**Dashboard / Docker**
- Read-only: nginx forwards only `GET` requests for hosts, incidents and stats, and blocks the
  ingest API. Strict Content-Security-Policy, no third-party scripts.
- Containers run as non-root users (`nginx-unprivileged`, a dedicated `edr` user), the server
  container is read-only with all capabilities dropped, and every port is published on
  `127.0.0.1` only. `.env` holds the only secrets and is git-ignored.
