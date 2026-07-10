# opcua-scanner

`opcua_recon.py` — a standalone **pre-authentication reconnaissance** module for
OPC-UA servers. It enumerates everything the protocol exposes *without
credentials* (endpoints, security policies, advertised auth methods, server
certificate, discovery records) and, only when explicitly asked, makes one
opt-in anonymous session attempt to read `ServerStatus`.

It never writes, never supplies credentials, and never crawls the address space.

> **Authorised use only.** Run this only against OPC-UA servers you own or have
> explicit written permission to assess.

## Install

```
pip install asyncua cryptography
```

Python 3.11+. No other third-party dependencies.

## Usage

```
opcua_recon.py opc.tcp://host:4840                  # passive enumeration of one target
opcua_recon.py opc.tcp://host:4840 --anon-probe     # add the OPT-IN anonymous session probe
opcua_recon.py --targets hosts.txt                  # one opc.tcp:// URL per line ('#' comments allowed)
opcua_recon.py opc.tcp://host:4840 --timeout 5      # per-connection timeout (default 5s)
opcua_recon.py opc.tcp://host:4840 --json out.json  # also write structured JSON
opcua_recon.py opc.tcp://host:4840 --csv out.csv    # also write a flat per-endpoint CSV
```

Human-readable output always goes to stdout. `--json` and `--csv` are additive
(you can pass both) and write structured/flat copies alongside the stdout report.

### What it collects

**Phase 1 — passive (no session, no credentials):**

- **GetEndpoints** — endpoint URLs (flagging NAT/multi-homed mismatches),
  security policy (normalised short name, deprecated policies flagged), message
  security mode, security level, advertised user-identity tokens (Anonymous /
  Username / Certificate / IssuedToken, each with its own policy), transport
  profile, and the embedded application descriptor.
- **Server certificate** — subject/issuer (self-signed noted), validity
  (expired / not-yet-valid flagged), key algorithm + length (short keys
  flagged), signature algorithm (SHA1 flagged), and SANs.
- **FindServers** — registered server records.
- **FindServersOnNetwork** — Local Discovery Server records, when an LDS is
  present (absence is handled gracefully).

These are unauthenticated discovery services by design: they run over a bare
OPC-UA SecureChannel and never create a session, which is why no credentials are
required.

**Phase 2 — active, `--anon-probe` only:**

- A single anonymous `connect()`; on success reads `ServerStatus` (build info,
  state, start/current time). Both acceptance and rejection are recorded as
  findings. The session is always closed cleanly.

### Derived findings

Computed from the collected data (no extra calls): SecurityMode=None offered,
Anonymous advertised, deprecated policy offered, expired/self-signed cert, short
key, SHA1 signature, anonymous session accepted/rejected, plus a
vendor/product/version fingerprint.

## Explicitly out of scope

No authenticated sessions, no writes/method-calls/subscriptions, no credential
guessing, no address-space crawling.
