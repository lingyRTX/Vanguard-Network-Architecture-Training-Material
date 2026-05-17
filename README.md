# Vanguard Network Architecture — Training Material

A case study in modern commercial anti-cheat network design.
Used as illustrative material for understanding how state-of-the-art anti-cheats structure their communication, what defenses each layer provides, and why specific design choices were made.

**Target audience**: Security researchers, system programmers, students of OS/network internals.
**Prerequisites**: Familiarity with TCP/IP, TLS, HTTP, basic Windows kernel concepts.

---

## Table of contents

1. [Introduction & learning goals](#1-introduction--learning-goals)
2. [System architecture](#2-system-architecture)
3. [The layered network model](#3-the-layered-network-model)
4. [Layer 1: DNS — endpoint discovery](#4-layer-1-dns--endpoint-discovery)
5. [Layer 2: TCP — transport](#5-layer-2-tcp--transport)
6. [Layer 3: TLS — encryption + identity](#6-layer-3-tls--encryption--identity)
7. [Layer 4: HTTP/2 — request semantics](#7-layer-4-http2--request-semantics)
8. [Layer 5: Custom headers — out-of-band signaling](#8-layer-5-custom-headers--out-of-band-signaling)
9. [Layer 6: Application envelope](#9-layer-6-application-envelope)
10. [Layer 7: Application body encryption](#10-layer-7-application-body-encryption)
11. [Local IPC channels](#11-local-ipc-channels)
12. [Defense-in-depth summary](#12-defense-in-depth-summary)
13. [Key takeaways for AC designers](#13-key-takeaways-for-ac-designers)

---

## 1. Introduction & learning goals

A modern anti-cheat service must transmit telemetry, receive command messages, and authenticate the client — all while running in a hostile environment where the user has full root on their own machine. The attacker can:

- Read all process memory
- Hook system APIs
- Modify the binary on disk
- Run kernel drivers
- Capture and replay network traffic
- Spoof DNS

The anti-cheat's network stack must remain trustworthy despite this. Understanding how a real production system achieves this is instructive for:

- Designing your own protected client-server protocols
- Researching how to identify weaknesses (defensive perspective)
- Understanding why certain "obvious" attacks (DNS hijack, MITM) don't work against well-designed AC

By the end of this document, you should understand:

- Why standard Windows TLS APIs are insufficient for AC
- The role of certificate pinning vs full chain validation
- How DNS-over-HTTPS prevents local DNS hijack
- Why anti-cheats build their own crypto stack on top of TLS
- The pattern of "metadata in HTTP headers, data in encrypted body"
- Local IPC design for cross-process trust

---

## 2. System architecture

The system has three primary processes (running on the user's machine) plus a remote backend:

```
                                        REMOTE
                              ┌────────────────────────┐
                              │  Riot backend (cloud)  │
                              │  microservice gateway  │
                              └────────────▲───────────┘
                                           │ HTTPS
                                           │
                              ┌────────────┴───────────┐
                              │   Cloudflare CDN edge  │  (TLS termination + bot mgmt)
                              └────────────▲───────────┘
                                           │
─────────────────────────────────────── HOST ──────────────────────────────
                                           │
                              ┌────────────┴───────────────────────────┐
                              │  vgc.exe  (Windows service, SYSTEM)    │
                              │  - libcurl + OpenSSL + CryptoPP        │
                              │  - HTTPS client                        │
                              │  - Named pipe server                   │
                              │  - Localhost TCP client                │
                              └──┬──────────┬────────────────┬─────────┘
                                 │          │                │
                       pipe IPC  │     IOCTL│           local TCP
                                 │          │                │
                                 ▼          ▼                ▼
                       ┌──────────────┐ ┌──────────┐  ┌──────────────┐
                       │ Riot Client  │ │ vgk.sys  │  │  vgm.exe     │
                       │ (game UI)    │ │ (kernel) │  │  (sandbox)   │
                       └──────────────┘ └──────────┘  └──────────────┘
```

Network communication exists at three boundaries:

1. **External HTTPS**: vgc.exe ↔ cloud backend (the focus of this document)
2. **Named pipe IPC**: vgc.exe ↔ Riot Client (local, but uses MessagePack wire format)
3. **Localhost TCP**: vgc.exe ↔ vgm.exe (local rendezvous + sandbox communication)

We will examine each, but spend most time on the external HTTPS channel — it's the most security-critical and most architecturally interesting.

---

## 3. The layered network model

Vanguard's external communication stack:

```
┌──────────────────────────────────────────────────────────────┐
│  Layer 7  │ Application body                                  │  AES-256-GCM
│           │ Inner protobuf (encrypted)                        │  app-layer crypto
├───────────┼───────────────────────────────────────────────────┤
│  Layer 6  │ Protobuf Envelope                                 │  Type + payload wrapper
│           │ { message_type, payload, request_id }             │  + magic "RG\x01\x00"
├───────────┼───────────────────────────────────────────────────┤
│  Layer 5  │ Custom HTTP headers (X-VG-*)                      │  Out-of-band metadata
├───────────┼───────────────────────────────────────────────────┤
│  Layer 4  │ HTTP/2 over TLS                                   │  Standard web
├───────────┼───────────────────────────────────────────────────┤
│  Layer 3  │ TLS 1.3 (with static OpenSSL inside vgc)          │  Transport encryption
├───────────┼───────────────────────────────────────────────────┤
│  Layer 2  │ TCP to Cloudflare edge IP                         │  Standard transport
├───────────┼───────────────────────────────────────────────────┤
│  Layer 1  │ DNS resolution (via DoH, bypassing local DNS)     │  Endpoint discovery
└───────────┴───────────────────────────────────────────────────┘
```

Note the **two encryption layers**:
- TLS encrypts the transport (Layer 3)
- AES-GCM additionally encrypts the application body (Layer 7)

Why both? **Defense in depth**: even if TLS is compromised (key extracted, MITM with pinned cert bypassed), the inner content remains encrypted. We'll explore this rationale in detail.

---

## 4. Layer 1: DNS — endpoint discovery

### Standard DNS (the vulnerability)

Normal Windows applications resolve hostnames via:
1. Check `C:\Windows\System32\drivers\etc\hosts`
2. Check local DNS cache
3. Query configured DNS server (router, ISP, public)

This is **trivially hijackable** by:
- Editing the hosts file (requires admin)
- Running a local DNS proxy
- ARP-spoofing the router on local LAN
- Compromising the upstream resolver

For an anti-cheat that must reach its backend, this is unacceptable. A user could redirect `vanguard.riotgames.com` → `127.0.0.1` and run their own server returning "you are not banned".

### Vanguard's solution: DNS-over-HTTPS (DoH)

vgc.exe configures libcurl with `CURLOPT_DOH_URL` pointing to a hardcoded DoH endpoint. This bypasses:
- The hosts file
- Local DNS cache
- System DNS configuration
- Router-level DNS

Instead, vgc sends DNS queries as HTTPS POST to a predetermined DoH provider, receiving signed DNS responses. The DoH endpoint is itself TLS-pinned, so even MITM on the DoH connection is detected.

**Observed gateway hostname** (resolved via DoH):
```
eu.vg.ac.pvp.net  →  CNAME → eu.vg.ac.pvp.net.cdn.cloudflare.net
                  →  104.18.41.168, 172.64.146.88 (Cloudflare AS13335)
```

Subdomain convention:
- `eu.vg.ac.pvp.net` — EU region
- Similar regional subdomains for NA, JP, etc.
- `vg` = Vanguard
- `ac` = Anti-Cheat
- `pvp.net` = Riot's gameplay infrastructure

### Cloudflare fronting (the strategic choice)

The fact that DNS resolves to Cloudflare IPs (not Riot-owned IPs) is significant. Cloudflare is a CDN/edge provider; the actual backend behind it is hidden. Benefits to Riot:

- **DDoS protection** (Cloudflare absorbs volumetric attacks)
- **Origin IP hiding** (attackers can't directly target Riot servers)
- **Bot management** (Cloudflare's bot detection adds an early filter — observed via `__cf_bm` cookie)
- **Geographic distribution** (low latency to users globally)

Trade-off: relies on Cloudflare's continued availability and trustworthiness. A Cloudflare outage takes down the anti-cheat backend.

**Learning point**: even high-security applications use commercial CDNs as a layer of indirection. The cert pinning (next section) still anchors trust to Riot's own keys, not Cloudflare's.

---

## 5. Layer 2: TCP — transport

Nothing unusual here. Standard TCP connection from vgc to the resolved IP on port **8443** (non-standard HTTPS port — some networks use this for traffic differentiation, but functionally identical to 443).

What's interesting is the **connection lifecycle**:

```
vgc.exe wants to talk to gateway
  ↓
[1] local TCP connect to 127.0.0.1:<ephemeral 51614+>
[2] send 9 random bytes
[3] recv 9 bytes echoed back   ← liveness probe to vgm sandbox
  ↓
[4] external TCP connect to 104.18.41.168:8443
[5] proceed with TLS handshake
```

The localhost step **(1-3)** is unusual. Before any external connection, vgc verifies a local service (vgm.exe) is alive by sending random bytes and expecting them echoed. If the local echo fails, the external request is not made.

**Purpose**: prevents an attacker who killed vgm.exe (the sandbox) from getting vgc to communicate with the server in a "compromised" local environment. It's a paranoid integrity check at the network layer.

**Observed**: every single external HTTPS request is preceded by this 9-byte localhost echo.

---

## 6. Layer 3: TLS — encryption + identity

### Why not use Windows SChannel?

The standard approach for Windows apps is to use SChannel (Windows' built-in TLS via secur32.dll / sspicli.dll). vgc deliberately does NOT do this.

Instead, vgc **statically links its own copy of OpenSSL 3.0.14** inside the executable. Why?

1. **API hooking resistance**: hooks on `secur32!EncryptMessage`, `secur32!DecryptMessage`, etc. — the standard chokepoints for intercepting TLS plaintext — fire zero times against vgc, because vgc never calls them.
2. **Version control**: vgc gets exactly the TLS implementation Riot tested, with known properties.
3. **Cipher control**: vgc can enforce TLS 1.3 only with a specific cipher list, regardless of system policy.
4. **Crypto material isolation**: TLS state lives in vgc's heap, not in lsass.exe (where SChannel keys live), making cross-process key extraction harder.

This is a defense pattern: **don't use Microsoft's built-in security boundaries**, because every attacker tool targets them. Build your own.

### TLS configuration

Captured from vgc's curl_easy_setopt calls:

| Option | Value | Meaning |
|---|---|---|
| `CURLOPT_HTTP_VERSION` | 3 (`HTTP/2.0`) | Force HTTP/2 |
| `CURLOPT_SSL_VERIFYPEER` | **0** | Cert chain NOT verified |
| `CURLOPT_SSL_VERIFYHOST` | (not set) | Uses default (=2, hostname check) |
| `CURLOPT_PINNEDPUBLICKEY` | (binary string present, but NOT observed being applied) | TLS pin |

**Cipher suites** (TLS 1.3 only):
```
TLS_AES_256_GCM_SHA384
TLS_CHACHA20_POLY1305_SHA256
TLS_AES_128_GCM_SHA256
TLS_AES_128_CCM_SHA256
TLS_AES_128_CCM_8_SHA256
```

All AEAD ciphers — authenticated encryption only.

### Certificate pinning — the concept

Normal TLS validates a certificate by checking:
1. Cert is signed by a CA in the trust store
2. Hostname matches the cert's CN/SAN
3. Cert hasn't expired or been revoked

The weakness: there are ~150 root CAs in Windows trust store. If ANY one of them is compromised (or if an attacker can add their own CA to trust store), they can issue a valid cert for `vg.ac.pvp.net` and MITM TLS.

**Certificate pinning** bypasses CA trust entirely. The client hardcodes the expected server certificate's public key hash:

```
sha256//PRk++DZH5llEWYvGZ90+VK4v32pUgPYXryL052kFySQ=
```

Now only the legitimate server (which has the matching private key) can present a cert with this SPKI hash. Even a maliciously-issued cert from a compromised CA won't match.

### Pin defeat strategies (and Vanguard's counters)

| Attack | Counter |
|---|---|
| Replace pin string in binary | Vanguard hashes its own .text section periodically to detect modification |
| Patch the pin-set instruction | Same self-integrity check |
| Hook `CURLOPT_PINNEDPUBLICKEY` setopt to skip | vgc has its own curl statically linked — no shared library boundary |
| Trick Windows to trust a malicious CA | Pin bypasses CA chain entirely |

### Observation: production pin behavior

Interestingly, in observed production runs, vgc did **NOT** set `CURLOPT_PINNEDPUBLICKEY` on any of the captured curl handles (168 setopt calls across one session). Also `CURLOPT_SSL_VERIFYPEER` was set to **0** (chain validation disabled).

Possible interpretations:
- The pin is set elsewhere (curl handle template, before our hooks installed)
- Production deliberately disabled pinning (less likely)
- Pinning is delegated to a different layer (less likely)

This is a teaching point: **what's documented in static analysis may differ from production runtime behavior**. Always verify with live observation.

---

## 7. Layer 4: HTTP/2 — request semantics

Vanguard uses HTTP/2 over TLS 1.3:

```http
POST /vanguard/v1/gateway HTTP/2
Host: eu.vg.ac.pvp.net:8443
User-Agent: vanguard/1.18.2-25+20260501.225940
Accept: */*
Content-Type: application/x-protobuf
X-VG-0: 6a0918617dcddb00010ef07f
X-VG-1: 9
X-VG-2: 435f24ed-8e1f-59a7-9bb7-a8318d3be723
X-VG-3: 1
X-VG-4: com.riotgames.league
Content-Length: 5991

<binary body — see Layer 6>
```

### Why HTTP/2?

- **Multiplexing**: multiple requests over one TCP+TLS connection (avoid handshake overhead)
- **Header compression** (HPACK)
- **Server push** (for command-and-control)
- **Binary framing** (faster parsing)

For a high-frequency telemetry channel (heartbeats every ~30s, task results, etc.), the connection reuse alone provides significant latency savings.

### Single-URL design

All client→server communication goes to a single endpoint: `/vanguard/v1/gateway`. The request body's protobuf envelope contains a `message_type` field that the server uses to route.

**Why one URL instead of REST-style endpoints**?

- **Easier to firewall**: only one path to allow
- **Simpler load balancer rules**: hash on session ID, not on URL
- **Hides protocol structure** from network observers (you can't tell from URL whether this is an auth, heartbeat, or task result)
- **Encryption** (Layer 7) makes the URL the only externally-visible discriminator anyway, so why have many?

### `User-Agent` exposes build version

```
vanguard/1.18.2-25+20260501.225940
```

This is informational (server uses it for analytics / outdated client rejection) but does leak the exact build identifier.

### `Content-Type: application/x-protobuf`

Tells the server the body is binary protobuf, not JSON or form data. Important because the body starts with bytes that are NOT valid JSON.

---

## 8. Layer 5: Custom headers — out-of-band signaling

```
X-VG-0: 6a0918617dcddb00010ef07f
X-VG-1: 9
X-VG-2: 435f24ed-8e1f-59a7-9bb7-a8318d3be723
X-VG-3: 1
X-VG-4: com.riotgames.league
```

Five anonymously-named headers. Each carries metadata that's available **before** the encrypted body is decrypted. The anonymous names (`X-VG-0` not `X-Vanguard-MachineId`) make protocol inference from packet captures harder.

### Decoded purpose

| Header | Format | Meaning |
|---|---|---|
| **X-VG-0** | MongoDB ObjectID hex (24 chars = 12 bytes) | Per-request tracking ID. Timestamp + per-process random + counter. |
| **X-VG-1** | Small integer | Message type discriminator — mirrors the inner Envelope's `message_type` for pre-decryption routing |
| **X-VG-2** | UUID v5 | **Machine ID** — SHA-1 namespaced hash over HWID components. Stable per machine, all sessions. |
| **X-VG-3** | Constant `1` | Protocol version |
| **X-VG-4** | Reverse-DNS app ID (e.g. `com.riotgames.league`) | Application context |

### Why mirror message_type in a header?

The body is encrypted (Layer 7). To decrypt, the server needs the session key. To find the session key, the server needs the session ID. To find the session ID... it has to know who you are.

**X-VG-2** (machine_id) allows the server to look up your session BEFORE decrypting the body. **X-VG-1** allows the server to route the encrypted request to the correct handler (heartbeat handler, auth handler, etc.) without decrypting.

This is the **"sealed envelope with shipping label"** pattern. The recipient name (X-VG-2) and category (X-VG-1) are on the outside; the contents are inside, encrypted. The mail carrier (Cloudflare edge) doesn't need to open it.

### Why ObjectID per-request?

`X-VG-0` is a unique per-request identifier. Server uses it for:

- **Deduplication**: if the same request arrives twice (network retry), respond from cache
- **Correlation**: server logs use this ID to trace one request across microservices
- **Replay detection**: timestamp embedded in ID makes old replayed requests detectable

The pattern is similar to AWS request IDs or Cloud Trace IDs — common in microservice architectures.

### Machine ID as UUID v5

UUID v5 = SHA-1 of (namespace UUID || name bytes), with version bits set. Properties:

- **Deterministic**: same input always produces same output
- **Compact**: 16 bytes, displayable as readable string
- **Looks random**: byte distribution is uniform, no obvious patterns

By hashing the HWID components into a UUID v5, the server gets a stable identifier without learning the raw HWID. (The actual HWID details ARE sent in the AUTH request body, but the lightweight per-request identifier is just the hash.)

---

## 9. Layer 6: Application envelope

After TLS decryption (Layer 3) and HTTP parsing (Layer 4), the server has the request body. This is a protobuf message:

```protobuf
message Envelope {
  MessageType message_type = 1;  // Same value as X-VG-1
  bytes       payload      = 2;  // ENCRYPTED inner message
  string      request_id   = 3;
}
```

### Wire format

```
offset   bytes                       meaning
00000000 08 0X                        protobuf field 1 (varint = message_type)
00000002 12 <varint>                  protobuf field 2 (length of payload bytes)
00000004 52 47 01 00                  MAGIC "RG\x01\x00"  (RiotGuardian, version 1, flags 0)
00000008 ... ciphertext ...           AES-256-GCM(session_key, inner_protobuf)
                                      = 12-byte nonce + ciphertext + 16-byte GCM auth tag
```

The 4-byte magic `RG\x01\x00` is a sanity check — server validates this before attempting decryption. If absent, the request is malformed (or from a wrong protocol version).

### Message types observed

| message_type | Name | Typical body size |
|---|---|---|
| 3 | ACCESS_REQUEST | small (~2737 B) — initial connection |
| 4 | AUTH_REQUEST | larger (~5870 B) — contains full HWID dump |
| 7 | HEARTBEAT_REQUEST | fixed (~5990 B) — keepalive |
| 9 | TASK_RESULT_REQUEST | variable (~5900-17000 B) — scan results |

Inner messages (after decryption) include `AuthenticationRequest`, `HeartbeatRequest`, `TaskResultRequest`. Full schema is ~25 message types covering auth, telemetry, module dispatch, task results, and disconnection.

---

## 10. Layer 7: Application body encryption

Here is where the design gets interesting. Inside the TLS-encrypted HTTPS, the application body is **also encrypted** with AES-256-GCM using a session key.

### Two-layer encryption rationale

Why double-encrypt?

| Scenario | TLS alone | TLS + app-layer |
|---|---|---|
| Network sniffer (no key) | Safe — TLS works | Safe |
| MITM with valid cert | **VULNERABLE** — TLS broken | Safe (app key unknown) |
| Compromised CA + DNS hijack | **VULNERABLE** | Safe |
| Extracted TLS session keys (e.g. SSLKEYLOGFILE) | **VULNERABLE** | Safe (app key separate) |
| Hook ON `SSL_write` in OpenSSL | **VULNERABLE** | Safe (sees only ciphertext) |
| Hook `BCryptEncrypt` (kernel crypto) | N/A | N/A (vgc uses CryptoPP, not BCrypt) |
| Hook CryptoPP `GCM<AES>::Encryption::ProcessData` | Safe | **VULNERABLE** |

This is true **defense in depth**: each layer protects against different attack vectors. Only an attacker who can hook deep into vgc's CryptoPP code (which is statically linked, in a 4 MB .text section) can see plaintext.

### Session key establishment

The session key is negotiated during the AUTH flow using a forward-secret RSA-OAEP wrap:

```
Client (vgc):                               Server:
  Generate ephemeral RSA-2048 keypair       Has long-term RSA pubkey (embedded in vgc)
  
  AuthenticationRequest {
    client_rsa_public_key: <our pub>,
    machine_id: ...,
    ephemeral_identifiers: [...HWID components SHA-256'd...],
    device_info: { cpu, gpu, memory, os },
    ...
  }
                          ─────────────→
                                              Generate random AES-256 session key
                                              Wrap: RSA-OAEP-SHA1(client_pub, session_key)
                                              Sign: RSA-PKCS1(server_priv, payload)
                                              
                                              TokenResponse {
                                                token: <session token>,
                                                exp: <expiry>,
                                                server_rsa_public_key: <for client to verify>,
                                                ephemeral_identifiers: [wrapped_session_key],
                                                session_id: <uuid>,
                                              }
                          ←─────────────
  Verify server_rsa_pubkey matches embedded
  Decrypt wrapped with client_priv → session_key
  All subsequent bodies: AES-GCM(session_key, payload)
```

### Why ephemeral client RSA?

The client generates a **new** RSA keypair every session. The private key never leaves vgc's heap and is destroyed at session end. Effects:

- **Forward secrecy**: if vgc is later compromised and the persistent server key is leaked, **past sessions remain safe** — the per-session AES key was encrypted with the ephemeral client key whose private half is gone
- **Replay resistance**: each session has a unique session_id and key
- **Limits damage from single-session compromise**

### Algorithm choices

- **RSA-2048 OAEP-SHA1**: asymmetric wrap. SHA1 here is mostly a hash function for OAEP padding — not used for collision-resistant signing. Adequate for OAEP.
- **AES-256-GCM**: symmetric AEAD. Industry standard.
- **CryptoPP** as the implementation library (not Windows CNG). Same reasoning as for TLS — control + isolation from system hooks.

---

## 11. Local IPC channels

External HTTPS is the most security-critical, but vgc has three other communication channels for local coordination.

### 11.1 Named pipe (vgc ↔ Riot Client)

```
Pipe path: \\.\pipe\933823D3-C77B-4BAE-89D7-A92B567236BC
Mode:      DUPLEX / MESSAGE
Security:  NULL DACL (anyone can connect)
Format:    MessagePack + nlohmann::json
```

The Riot Client (game launcher, runs as user) talks to vgc (runs as SYSTEM) via this pipe. Use cases:
- Riot Client asks vgc "are you authenticated?"
- vgc tells Riot Client "block game launch — VAN-152 ban"
- HWID/PUUID queries

**NULL DACL = no access control**. Anyone can connect to this pipe. Security comes from the data layer:
- vgc challenges the client with a crypto handshake on first connect
- Messages are signed/encrypted (verified via NULL DACL being acceptable)

This is "**network security through crypto, not OS permissions**" pattern.

The pipe uses a fixed GUID as its name (`933823D3-C77B-4BAE-89D7-A92B567236BC`). Hardcoded, never changes — used as a known-location rendezvous point.

### 11.2 Localhost TCP (vgc ↔ vgm.exe)

Used for the 9-byte echo rendezvous described in Section 5. Also used to deliver downloaded **Module DLLs** to the sandbox process (vgm) for execution.

When the server pushes a Module (via the `ModulesResponse` message), vgc:
1. Downloads the signed DLL from a CDN URL
2. Verifies the RSA signature (via `BCryptVerifySignature` in kernel)
3. Sends the verified DLL bytes over localhost TCP to vgm
4. vgm calls `LoadLibraryExW` on the bytes in its sandboxed environment
5. vgm reports execution result back through the same channel

The localhost protocol details are encrypted, so analysis from outside is limited.

### 11.3 IOCTL (vgc ↔ vgk.sys)

Not "network" strictly, but it's the third communication channel. vgc sends IOCTL codes (commands) to its kernel driver vgk.sys to request privileged operations:

- Read MSRs (CPUID extensions, IA32_PLATFORM_ID for Intel)
- Read disk serial numbers via `IOCTL_STORAGE_QUERY_PROPERTY`
- Query process state (for scanning other processes)
- Get TPM EK public key hash

20 distinct IOCTL function codes observed, all on device type `0x0022` (FILE_DEVICE_UNKNOWN — custom).

The interesting design choice: vgc uses **4 separate device handles** simultaneously, presumably for different "command channels" (HWID queries, scan commands, status queries, etc.). Suggests the kernel driver exposes multiple device objects with distinct purposes.

---

## 12. Defense-in-depth summary

What attacks does this architecture defeat at each layer?

| Layer | Attack | Defense |
|---|---|---|
| DNS | hosts file redirect | DoH bypasses local resolution |
| DNS | DNS server poisoning | DoH uses pinned remote DoH provider |
| TCP | Port blocking | Standard port 8443 (allowable in most firewalls) |
| TLS | MITM with self-signed cert | (Pin would defeat this; in observed prod, only hostname check) |
| TLS | MITM with valid cert from compromised CA | App-layer AES-GCM still encrypted |
| TLS | Hook `BCryptEncrypt` (Windows crypto) | vgc doesn't use Windows crypto |
| TLS | Hook `SChannel!EncryptMessage` | vgc doesn't use SChannel |
| HTTP | Replay attack | X-VG-0 ObjectID has timestamp; server rejects stale |
| HTTP | URL/path-based filtering by attacker | Only one URL exists |
| Application | Sniff body content | Body encrypted with session key |
| Application | Decrypt with leaked TLS key | App-layer key is separate |
| Application | Forge AUTH request with fake HWID | Server has banlist of HWID components — any match denies |
| Application | Replay AUTH request | Per-session ephemeral client key |
| Local | Kill vgm sandbox | 9-byte localhost echo fails → no external request |
| Local | Hijack pipe name | Pipe message protocol is crypto-secured |
| Local | Read pipe via NULL DACL | Messages encrypted |

Note the pattern: **each layer assumes the layer below it might fail**. The system as a whole only fails if MANY layers are simultaneously broken.

---

## 13. Key takeaways for AC designers

If you are designing a similar protected client-server protocol, the lessons are:

1. **Don't use Microsoft's built-in security primitives**. Every attacker tool targets them. Statically link your own crypto.

2. **DoH for DNS** — local DNS is hostile territory. Bypass it.

3. **Use a CDN for fronting** — operational benefits + obscures backend.

4. **Pin certificates**, but verify pinning is actually enabled in production builds (static analysis can mislead).

5. **Two encryption layers** — TLS for transport, app-layer AES-GCM for content. Each defeats different attacker capabilities.

6. **Per-session ephemeral keys** with forward secrecy. Limits damage from single compromise.

7. **Metadata in HTTP headers, data in encrypted body**. Server can route without decrypting.

8. **Unique request IDs with embedded timestamps**. Replay detection + tracing.

9. **Single URL endpoint**. Simpler firewall rules; nothing leaks from URL structure.

10. **Local liveness checks before external requests**. Prevents requests in compromised local state.

11. **Define a clear application-layer envelope** with magic bytes for sanity checking. Easy to detect malformed/wrong-version requests.

12. **Defense in depth**. No single layer's failure compromises the system.

For students wanting to learn more, the next step is to study how each of these patterns is implemented in your language/framework of choice. Examples worth studying:
- gRPC with mutual TLS (similar pattern but standard)
- WireGuard handshake (related: ephemeral keys + forward secrecy)
- Signal protocol (related: layered encryption, forward secrecy)
- CloudFlare's bot management documentation (related: edge filtering)

---

## Appendix: Glossary

| Term | Meaning |
|---|---|
| AEAD | Authenticated Encryption with Associated Data — encryption that also includes integrity check |
| CDN | Content Delivery Network — geographically distributed edge servers |
| CA | Certificate Authority — issues TLS certs |
| DoH | DNS-over-HTTPS — DNS queries sent as HTTPS POST |
| EX_CALLBACK | Windows kernel callback structure for system event handlers |
| HPACK | HTTP/2 header compression |
| HWID | Hardware Identifier — composite fingerprint of physical device |
| IPC | Inter-Process Communication |
| MITM | Man-In-The-Middle — attacker sits between client and server |
| OAEP | Optimal Asymmetric Encryption Padding — secure padding for RSA |
| SAN | Subject Alternative Name — cert field listing valid hostnames |
| SChannel | Microsoft's Secure Channel — Windows' built-in TLS implementation |
| SPKI | Subject Public Key Info — DER-encoded public key from a cert |
| TLS | Transport Layer Security — protocol for encrypted transport |
| UUID v5 | Universally Unique Identifier, version 5 — SHA-1-derived |

---

## Appendix: References for further study

- RFC 7858 — DNS over Transport Layer Security (DoT)
- RFC 8484 — DNS Queries over HTTPS (DoH)
- RFC 8446 — TLS 1.3
- RFC 7540 — HTTP/2
- RFC 5116 — AEAD interface
- RFC 4122 — UUID specification
- "Bulletproof SSL and TLS" by Ivan Ristić
- "Network Security Assessment" by Chris McNab
- OpenSSL `apps/openssl-cli` documentation
- libcurl `CURLOPT_*` documentation at curl.se
- CryptoPP wiki at cryptopp.com
- Cloudflare developer docs on Bot Management
