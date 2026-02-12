# Agent Skill Attestation Format (ASAF)

**Version:** 1.0-draft

**Status:** Draft

**Domain:** haldir.ai

**Reference Implementation:** [haldir](https://github.com/haldir-ai/haldir)

**License:** Apache 2.0

---

## Abstract

This specification defines a framework-agnostic format for cryptographically signing, verifying, and revoking agent skills and MCP servers. It provides tamper-evident integrity, publisher authentication, permission declarations, and signed revocation through a `.vault/` security envelope placed alongside standard skill files.

The format is built on established standards: DSSE v1.0.0 for signature envelopes, RFC 8785 (JCS) for canonical JSON, Ed25519 (RFC 8032) for digital signatures, and SHA-256 (FIPS 180-4) for integrity hashing.

## Motivation

Agent skills are distributed without integrity verification, publisher authentication, or revocation capability. In February 2026, the ClawHavoc incident revealed 341 malicious skills (12% of a major public registry) deploying credential stealers, reverse shells, and prompt injection payloads. Independent analysis found prompt injection in 36% of skills across major registries.

No existing agent framework or registry implements cryptographic signing at the skill package level. The CoSAI whitepaper (January 2026) explicitly recommends "cryptographic integrity remote attestation" for MCP servers but notes implementation details "remain unspecified."

This specification fills that gap.

## Design Goals

1. **Framework-agnostic.** Works with SKILL.md, MCP servers, or any directory-based skill format.
2. **Offline-capable.** Verification requires only the skill directory, a trusted key, and an optional revocation list. No network calls.
3. **Sigstore-compatible.** The DSSE envelope format is directly compatible with Sigstore keyless signing and Rekor transparency logs.
4. **No registry dependency.** The format is self-contained. Registries are optional distribution channels, not trust anchors.
5. **Deterministic.** Same inputs always produce identical bytes. Canonical JSON (RFC 8785) eliminates serialization ambiguity.
6. **Fail-fast.** Verification checks are ordered by cost and severity. The first failure terminates verification.

## Normative References

| Reference | Version | Usage |
|-----------|---------|-------|
| [DSSE](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md) | v1.0.0 | Signature envelope format, PAE construction |
| [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) | June 2020 | JSON Canonicalization Scheme (JCS) |
| [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) | January 2017 | Ed25519 digital signatures |
| [FIPS 180-4](https://csrc.nist.gov/publications/detail/fips/180/4/final) | August 2015 | SHA-256 hash function |
| [RFC 4648 Section 5](https://www.rfc-editor.org/rfc/rfc4648#section-5) | October 2006 | base64url encoding |
| [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) | March 1997 | Requirement level keywords |

---

## 1. Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in RFC 2119.

| Term | Definition |
|------|-----------|
| **Skill directory** | Any directory containing agent skill or MCP server files. The unit of signing and verification. |
| **Envelope** | The `.vault/` subdirectory within a skill directory, containing the four metadata files that constitute the security envelope. |
| **Publisher** | The entity that signs a skill directory. Identified by a key ID derived from their Ed25519 public key, or by an OIDC identity when using Sigstore keyless signing. |
| **Consumer** | The entity that verifies a skill directory before installation or during runtime. |
| **Trust level** | A machine-readable signal indicating verification confidence: `full`, `degraded`, or `none`. |
| **Context** | The verification scenario: `install` (fail-closed revocation) or `runtime` (fail-open with bounded grace). |
| **Key ring** | A mapping of key IDs to Ed25519 public keys, representing the set of publishers trusted by the consumer. |
| **Revocation list** | A signed, timestamped document listing skills that MUST NOT be installed or continued. |

---

## 2. Envelope Format

### 2.1 Directory Structure

```
<skill-directory>/
├── SKILL.md                  # Or any skill / MCP server files
├── config.json
├── ...
└── .vault/
    ├── signature.json        # DSSE v1.0.0 envelope (signs the attestation)
    ├── attestation.json      # Signed payload: metadata + integrity hash + permissions hash
    ├── integrity.json        # File-level SHA-256 allowlist
    └── permissions.json      # Declared capabilities
```

The `.vault/` directory MUST contain exactly these four files.

Files within `.vault/` are excluded from integrity hashing. All other files in the skill directory (including dotfiles and subdirectories) are covered by `integrity.json`.

### 2.2 Write Determinism

`attestation.json` and `integrity.json` MUST be written as canonical JSON per RFC 8785:
- UTF-8 encoding, no BOM
- No trailing newline
- No whitespace of any kind
- Object keys sorted by UTF-16 code unit

`signature.json` and `permissions.json` SHOULD be written as pretty-printed JSON (2-space indent, trailing newline) for human readability. They are not integrity-hashed directly.

The SHA-256 hash of `integrity.json` in the attestation is computed over the canonical JSON bytes as written to disk. The SHA-256 hash of permissions in the attestation is computed over the canonical JSON serialization of the permissions object.

---

## 3. File Formats

### 3.1 signature.json

The signature envelope follows DSSE v1.0.0 with one addition: `schema_version` for format versioning.

```json
{
  "schema_version": "1.0",
  "payloadType": "application/vnd.haldir.attestation+json",
  "payload": "<base64url(canonical JSON bytes of attestation)>",
  "signatures": [
    {
      "keyid": "<key identifier>",
      "sig": "<base64url(Ed25519_sign(PAE(payloadType, rawPayloadBytes)))>"
    }
  ]
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | REQUIRED | MUST be a value in the supported versions set. Currently: `"1.0"`. |
| `payloadType` | string | REQUIRED | MUST be `"application/vnd.haldir.attestation+json"`. |
| `payload` | string | REQUIRED | base64url encoding (RFC 4648 Section 5, no padding) of the canonical JSON bytes of the attestation. |
| `signatures` | array | REQUIRED | MUST contain at least one entry. Each entry has `keyid` (string, non-empty) and `sig` (string, non-empty). |

**PAE Construction (DSSE-derived, Haldir-specific):**

```
PAE(payloadType, payload) =
  "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
```

Where:
- `SP` = `0x20` (space byte)
- `LEN(s)` = ASCII decimal representation of the byte length of `s`
- `payload` = raw payload bytes (pre-base64). The base64url encoding in the envelope is for transport only.
- The signature is computed over the PAE output, NOT over the base64url string.

> **Note:** The upstream DSSE v1.0.0 specification uses 8-byte little-endian integers for `LEN()`. Haldir uses ASCII decimal strings instead. This means Haldir envelopes are **not interoperable** with generic DSSE verifiers (sigstore, in-toto). Sign and verify within Haldir are consistent. The Sigstore keyless path uses the sigstore library's own PAE internally.

The `signatures` array supports multiple entries for dual-sign scenarios (e.g., publisher + platform attestation). Implementations MUST support multiple entries. In v1.0, a single entry is typical.

### 3.2 attestation.json

The attestation is the signed payload. It is written as canonical JSON (RFC 8785) and these exact bytes are what gets base64url-encoded into `signature.json` and signed via PAE.

```json
{"integrity_hash":"sha256:a1b2...64chars","permissions_hash":"sha256:c3d4...64chars","schema_version":"1.0","signed_at":"2026-02-07T10:01:00Z","skill":{"name":"quote-generator","type":"skill.md","version":"1.0.0"}}
```

Human-readable equivalent:

```json
{
  "schema_version": "1.0",
  "skill": {
    "name": "quote-generator",
    "version": "1.0.0",
    "type": "skill.md"
  },
  "integrity_hash": "sha256:a1b2...64chars",
  "permissions_hash": "sha256:c3d4...64chars",
  "signed_at": "2026-02-07T10:01:00Z"
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | REQUIRED | MUST be a supported version. Currently: `"1.0"`. |
| `skill.name` | string | REQUIRED | Skill identifier. Non-empty. |
| `skill.version` | string | REQUIRED | Skill version. Non-empty. SHOULD follow semver. |
| `skill.type` | string | REQUIRED | Package type. Registered values: `"skill.md"`, `"mcp"`. Implementations MAY define additional types. |
| `integrity_hash` | string | REQUIRED | SHA-256 hash of the raw bytes of `integrity.json` as written to disk. Format: `sha256:<64 lowercase hex>`. |
| `permissions_hash` | string | REQUIRED | SHA-256 hash of the canonical JSON serialization of the permissions object (parsed from `permissions.json`). Format: `sha256:<64 lowercase hex>`. |
| `signed_at` | string | REQUIRED | ISO 8601 UTC timestamp of signing. |
| `_critical` | array of strings | OPTIONAL | Field paths that MUST be understood by the verifier. See Section 3.2.1. |

**Signer identity:** There is no `signer` field in the attestation. Signer identity lives exclusively in `signature.json` `signatures[].keyid`. This eliminates identity drift between the attestation and the signature envelope.

#### 3.2.1 Critical Fields

The `_critical` array lists field paths that a verifier MUST recognize and process. If a verifier encounters a field path in `_critical` that it does not recognize, it MUST reject the attestation with error code `E_UNKNOWN_CRITICAL`.

This mechanism allows adding new required fields to attestations without bumping the schema version, enabling forward-compatible evolution.

```json
{
  "schema_version": "1.0",
  "_critical": ["vetting.sandbox_required"],
  "skill": { "..." },
  "vetting": { "sandbox_required": true }
}
```

v1.0 attestations are not expected to use `_critical`, but verifiers MUST check for its presence.

### 3.3 integrity.json

The integrity manifest is a file-level SHA-256 allowlist. It is written as canonical JSON (RFC 8785). The SHA-256 of these exact bytes is stored as `integrity_hash` in the attestation.

```json
{"algorithm":"sha256","files":{"SKILL.md":"sha256:7d2f...64chars","config.json":"sha256:1a2b...64chars"},"generated_at":"2026-02-07T10:01:00Z","schema_version":"1.0"}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | REQUIRED | MUST be a supported version. Currently: `"1.0"`. |
| `algorithm` | string | REQUIRED | MUST be `"sha256"` in v1.0. |
| `files` | object | REQUIRED | Mapping of relative file paths to hash strings. |
| `generated_at` | string | REQUIRED | ISO 8601 UTC timestamp of manifest generation. |

**Path rules for `files` keys:**

| Rule | Detail |
|------|--------|
| Separator | Forward slash `/` only. On Windows, normalize `\` to `/` before hashing or comparing. |
| Relativity | Relative to the skill directory root. No leading `./` or `/`. |
| Ordering | Sorted by UTF-8 byte order (consistent with RFC 8785 key sorting). |
| Case | Always case-sensitive. `README.md` and `readme.md` are distinct. |
| Hidden files | Included. Dotfiles are hashed like any other file. |
| `.vault/` | Excluded. The envelope directory is never part of the integrity manifest. |
| Encoding | UTF-8. No Unicode normalization. Raw bytes compared. |
| Directories | Only regular files are hashed. Empty directories are not tracked. |
| Newlines | Files are hashed as raw bytes. No CR/LF normalization. |

This manifest is an **allowlist**. Any file present in the skill directory that does not appear in `files` (excluding `.vault/`) causes verification to fail.

### 3.4 permissions.json

Permission declarations describe the capabilities a skill claims to need. Written as pretty-printed JSON for human readability.

```json
{
  "schema_version": "1.0",
  "declared": {
    "filesystem": {
      "read": ["./data/", "./templates/"],
      "write": ["./data/output/"]
    },
    "network": "none",
    "exec": [],
    "agent_capabilities": {
      "memory_read": true,
      "memory_write": true,
      "spawn_agents": false,
      "modify_system_prompt": false
    }
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | REQUIRED | MUST be a supported version. Currently: `"1.0"`. |
| `declared` | object | REQUIRED | The capability declarations. |
| `declared.filesystem` | object | OPTIONAL | `read`: array of path globs. `write`: array of path globs. |
| `declared.network` | string or array | OPTIONAL | `"none"` for no network, or array of allowed domains/URLs. |
| `declared.exec` | array | OPTIONAL | Commands the skill claims to execute. |
| `declared.agent_capabilities` | object | OPTIONAL | `memory_read`, `memory_write`, `spawn_agents`, `modify_system_prompt` (all boolean). |

**Extensibility:** All objects in the permissions schema MUST preserve unknown fields (passthrough). This allows future extensions without breaking existing verifiers. Unknown fields are included in the permissions hash.

**Enforcement:** v1.0 permissions are informational only. They are verified (hash-bound to the attestation, so tampering is detectable) but NOT enforced at runtime. Enforcement is the responsibility of the hosting platform and is expected in a future version. Consumers MUST NOT rely on permissions for security decisions until enforcement is specified.

---

## 4. Hash String Format

All hash values in this specification use the following format:

```
sha256:<hex>
```

| Rule | Detail |
|------|--------|
| Prefix | Literal `sha256:` (lowercase, no spaces) |
| Hex digits | Exactly 64 characters, lowercase `[0-9a-f]` only |
| Full pattern | `^sha256:[0-9a-f]{64}$` |
| Parser behavior | Split on first `:`. Prefix MUST be `sha256`. Remainder MUST be exactly 64 lowercase hex chars. Any deviation MUST be rejected. |
| Comparison | Constant-time via `timingSafeEqual` (or equivalent) on the decoded byte buffers. String comparison MUST NOT be used for security-sensitive hash verification. |

The prefix allows future algorithm extensibility (e.g., `sha384:`, `sha512:`, `blake3:`) without format changes.

---

## 5. Canonical JSON (RFC 8785 / JCS)

All signed payloads (`attestation.json`, `integrity.json`) and revocation list payloads MUST use RFC 8785 JSON Canonicalization Scheme.

This is NOT "sorted keys with no whitespace." RFC 8785 specifies exact behavior for edge cases:

| Concern | RFC 8785 Rule |
|---------|---------------|
| Object keys | Sorted by UTF-16 code unit (not locale-dependent). |
| Whitespace | None. No spaces, newlines, or tabs. |
| Numbers | IEEE 754 shortest representation. No leading zeros, no positive sign, no trailing zeros after decimal. `1.0` becomes `1`, `1.00e2` becomes `100`. |
| Strings | UTF-8, minimal escaping. Only `"`, `\`, and control chars (`\u0000` through `\u001F`) are escaped. No unnecessary `\uXXXX` for printable characters. Surrogate pairs for characters outside BMP. |
| Unicode | No normalization (NFC/NFD). Raw code points preserved. |
| null / boolean | Literal `null`, `true`, `false`. |
| Arrays | Preserve insertion order. |

Implementations MUST use a tested RFC 8785 library. The library version SHOULD be pinned (exact, not range) and accompanied by compatibility tests that verify behavior against known RFC 8785 test vectors. If the library is updated, compatibility tests MUST pass before the update is accepted.

---

## 6. Signing Procedure

To create an envelope for a skill directory:

1. **Check filesystem safety.** Enumerate all entries in the skill directory recursively using `lstat` (not `stat`). Reject if any entry is a symlink, any regular file has `nlink > 1`, file count exceeds 10,000, any file exceeds 100 MB, or total size exceeds 500 MB. Reject if any file path resolves outside the skill directory root.

2. **Hash all files.** For each regular file (excluding `.vault/`), compute `sha256:<hex>` of the raw file bytes. Build a `files` object with forward-slash relative paths as keys, sorted by UTF-8 byte order.

3. **Build the integrity object.** Construct the integrity manifest with `schema_version`, `algorithm`, `files`, and `generated_at`.

4. **Write integrity.json.** Serialize the integrity object as canonical JSON (RFC 8785). Write to `.vault/integrity.json`. No BOM, no trailing newline.

5. **Build the permissions object.** Construct permissions from publisher-supplied declarations or empty defaults.

6. **Compute hashes.** `integrity_hash` = SHA-256 of `integrity.json` bytes as written. `permissions_hash` = SHA-256 of canonical JSON serialization of the permissions object.

7. **Build the attestation object.** Construct the attestation with `schema_version`, `skill`, `integrity_hash`, `permissions_hash`, and `signed_at`.

8. **Write attestation.json.** Serialize the attestation as canonical JSON (RFC 8785). Write to `.vault/attestation.json`. No BOM, no trailing newline.

9. **Encode and sign.** Encode the attestation bytes as base64url (no padding). Compute `PAE(payloadType, rawAttestationBytes)`. Sign the PAE output with the publisher's Ed25519 private key.

10. **Write signature.json.** Construct the DSSE envelope with `schema_version`, `payloadType`, `payload` (base64url of attestation bytes), and `signatures` array. Write as pretty-printed JSON.

11. **Write permissions.json.** Write the permissions object as pretty-printed JSON.

---

## 7. Verification Contract

### 7.1 Inputs

```
skillDir:                    string                    — path to the skill directory
trustedKeys:                 { [keyId: string]: PEM }  — trusted key ring
context:                     "install" | "runtime"     — determines revocation freshness policy
revocationList?:             SignedRevocationList       — signed revocation list (REQUIRED for install, optional for runtime)
lastValidRevocationList?:    SignedRevocationList       — fallback for runtime degraded mode (see Section 8.6)
cachedSequenceNumber?:       number                    — last-known revocation sequence for rollback detection
skipHardlinkCheck?:          boolean                   — only honored when context is "runtime" (ignored for install)
```

All inputs marked `?` are optional. `revocationList` is technically optional but its absence triggers `E_REVOCATION_STALE` in install context (Section 8.4).

### 7.2 Verification Checks

Checks are executed in order. The first failure terminates verification and returns the error.

| # | Check | Error Code | Message |
|---|-------|------------|---------|
| 1 | `.vault/` directory exists in skill directory | `E_NO_ENVELOPE` | `.vault/ directory not found` |
| 2 | All required files present: `signature.json`, `attestation.json`, `integrity.json`, `permissions.json` | `E_INCOMPLETE` | `Missing required file: {filename}` |
| 3 | No symlinks anywhere in skill directory (recursive `lstat`) | `E_SYMLINK` | `Symlink detected: {path}` |
| 4 | No hard links on regular files (`nlink > 1`). Skipped only if `skipHardlinkCheck` is true AND `context` is `"runtime"`. | `E_HARDLINK` | `Hard link detected: {path}` |
| 5 | File count ≤ 10,000 | `E_LIMITS` | `File count {n} exceeds limit` |
| 6 | No single file > 100 MB | `E_LIMITS` | `File {path} exceeds size limit` |
| 7 | Total size ≤ 500 MB | `E_LIMITS` | `Total size exceeds limit` |
| 8 | Parse `signature.json`, validate against schema | `E_INVALID_ENVELOPE` | `Signature envelope failed validation: {details}` |
| 9 | `schema_version` is in supported versions | `E_UNSUPPORTED_VERSION` | `Unsupported signature schema version: {v}` |
| 10 | At least one `signatures[]` entry has a `keyid` present in `trustedKeys`. Try each matching entry (steps 11-14). If any passes, use it. | `E_UNKNOWN_KEY` / `E_BAD_SIGNATURE` | See Section 7.3. |
| 11 | Decode `payload` from base64url to raw bytes | `E_DECODE_FAILED` | `Payload base64url decoding failed` |
| 12 | Compute `PAE(payloadType, rawPayloadBytes)` per DSSE v1.0.0 | — | Internal step. |
| 13 | Decode candidate `sig` from base64url to 64 bytes | `E_DECODE_FAILED` | `Signature base64url decoding failed` |
| 14 | Ed25519 verify: `verify(PAE, sigBytes, publicKey)` | `E_BAD_SIGNATURE` | `Ed25519 signature verification failed` |
| 15 | Parse decoded payload as JSON, validate against attestation schema | `E_INVALID_ATTESTATION` | `Attestation failed validation: {details}` |
| 16 | Attestation `schema_version` is in supported versions | `E_UNSUPPORTED_VERSION` | `Unsupported attestation schema version: {v}` |
| 17 | Raw bytes of `.vault/attestation.json` on disk == decoded payload bytes from step 11 (byte-for-byte) | `E_INTEGRITY_MISMATCH` | `attestation.json on disk does not match signed payload` |
| 18 | If `_critical` is present, every listed field path MUST be recognized by the verifier | `E_UNKNOWN_CRITICAL` | `Unrecognized critical field: {field}` |
| 19 | SHA-256 of `.vault/integrity.json` raw bytes == `attestation.integrity_hash` (constant-time) | `E_INTEGRITY_MISMATCH` | `integrity.json hash mismatch` |
| 20 | Parse `.vault/integrity.json`, validate against schema | `E_INVALID_INTEGRITY` | `Integrity manifest failed validation: {details}` |
| 21 | Integrity `schema_version` is in supported versions | `E_UNSUPPORTED_VERSION` | `Unsupported integrity schema version: {v}` |
| 22 | For each file in `integrity.files`: SHA-256 of raw bytes == declared hash (constant-time) | `E_INTEGRITY_MISMATCH` | `File hash mismatch: {filepath}` |
| 23 | Enumerate all files in skill directory excluding `.vault/`. Every file MUST appear in `integrity.files`. | `E_EXTRA_FILES` | `Undeclared file: {filepath}` |
| 24 | Parse `.vault/permissions.json`, validate against schema. If parsing or validation fails, return error. Otherwise compute SHA-256 of canonical JSON serialization of parsed permissions == `attestation.permissions_hash` (constant-time). | `E_INVALID_ENVELOPE` / `E_INTEGRITY_MISMATCH` | Parse/schema failure: `permissions.json failed validation: {details}`. Hash mismatch: `permissions.json hash mismatch`. |
| 25 | Revocation check (context-dependent, see Section 8) | `E_REVOKED` / `E_REVOCATION_STALE` | See Section 8. |

Note: Check 17 ensures that the `attestation.json` file on disk has not been replaced after signing. Since the signed payload is embedded in `signature.json` as base64url, an attacker could replace `attestation.json` on disk with different content while the signature still verifies against the original embedded payload. This check detects that divergence.

### 7.3 Multi-Signature Verification

When `signatures[]` contains multiple entries:

1. Collect all entries whose `keyid` exists in `trustedKeys`. If none match, return `E_UNKNOWN_KEY` immediately.
2. For each matching entry, attempt steps 11-14. Track whether each failure is a decode error (step 11 or 13) or a signature error (step 14).
3. If any entry passes all of steps 11-14, use it. Return its `keyid` as the verified signer. Stop iterating.
4. If all matching entries fail:
   - If every failure was a decode error (base64url decoding), return `E_DECODE_FAILED`.
   - If any failure reached step 14 (Ed25519 verify returned false), return `E_BAD_SIGNATURE`.
   - `E_BAD_SIGNATURE` takes precedence over `E_DECODE_FAILED` because reaching step 14 indicates a structurally valid but cryptographically incorrect signature, which is the more specific and informative error.

This approach avoids ordering fragility and supports future dual-sign (publisher + platform) without requiring the consumer to know which entry to check.

### 7.4 Output

```
valid:         boolean
trustLevel:    "full" | "degraded" | "none"
warnings:      [{ code: WarningCode, message: string }]
errors:        [{ code: ErrorCode, message: string, file?: string }]
attestation?:  Attestation    — present only when valid is true
permissions?:  Permissions    — present only when valid is true
keyId?:        string         — the keyid whose signature verified
```

**Trust levels:**

| Level | Meaning |
|-------|---------|
| `full` | All checks passed. Revocation list is valid and current. |
| `degraded` | Signature and integrity verified, but revocation check was incomplete (list unavailable, stale, or signature invalid in runtime context). |
| `none` | Verification failed. Skill MUST NOT be installed or continued. |

### 7.5 Error Codes

| Code | Description |
|------|-------------|
| `E_NO_ENVELOPE` | `.vault/` directory not found. |
| `E_INCOMPLETE` | One or more required `.vault/` files missing. |
| `E_SYMLINK` | Symlink detected in skill directory. |
| `E_HARDLINK` | Hard link detected on a regular file. |
| `E_LIMITS` | File count, file size, or total size limit exceeded. |
| `E_INVALID_ENVELOPE` | Envelope file failed schema validation (`signature.json` or `permissions.json`). |
| `E_UNSUPPORTED_VERSION` | Schema version not in the supported set. |
| `E_UNKNOWN_KEY` | No `keyid` in `signatures[]` matches `trustedKeys`. |
| `E_DECODE_FAILED` | base64url decoding failed for payload or signature. |
| `E_BAD_SIGNATURE` | Ed25519 signature verification failed. |
| `E_INVALID_ATTESTATION` | Attestation payload failed schema validation. |
| `E_UNKNOWN_CRITICAL` | Unrecognized field listed in `_critical`. |
| `E_INVALID_INTEGRITY` | `integrity.json` failed schema validation. |
| `E_INTEGRITY_MISMATCH` | Hash mismatch (integrity.json hash, file hash, permissions hash) or attestation.json on disk diverges from signed payload. |
| `E_EXTRA_FILES` | File present in skill directory but not in `integrity.files`. |
| `E_REVOKED` | Skill appears in the active revocation list. |
| `E_REVOCATION_STALE` | Revocation list missing, expired, or rolled back (install context). |

### 7.6 Warning Codes

| Code | Description |
|------|-------------|
| `W_REVOCATION_UNAVAILABLE` | No revocation list provided (runtime context). |
| `W_REVOCATION_STALE` | Revocation list expired but within grace period (runtime context). |
| `W_REVOCATION_SIG_INVALID` | Revocation list signature invalid; fallback used or unavailable (runtime context). |

---

## 8. Revocation

### 8.1 Revocation List Format

```json
{
  "schema_version": "1.0",
  "sequence_number": 42,
  "issued_at": "2026-02-07T12:00:00Z",
  "expires_at": "2026-02-08T12:00:00Z",
  "next_update": "2026-02-07T12:30:00Z",
  "entries": [
    {
      "name": "malicious-helper",
      "versions": ["*"],
      "revoked_at": "2026-02-07T11:30:00Z",
      "reason": "credential exfiltration",
      "severity": "critical"
    }
  ],
  "signature": {
    "keyid": "revoke-key-2026-01",
    "sig": "<base64url(Ed25519 over canonical JSON of all fields above signature)>"
  }
}
```

**Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `schema_version` | string | REQUIRED | MUST be a supported version. Currently: `"1.0"`. |
| `sequence_number` | integer | REQUIRED | Positive, monotonically increasing. Used for rollback detection. |
| `issued_at` | string | REQUIRED | ISO 8601 UTC. When the list was generated. |
| `expires_at` | string | REQUIRED | ISO 8601 UTC. Hard expiry. After this time (plus clock skew tolerance), the list is untrusted. |
| `next_update` | string | REQUIRED | ISO 8601 UTC. Soft polling hint for consumers. |
| `entries` | array | REQUIRED | Array of revocation entries. May be empty. |
| `signature` | object | REQUIRED | `keyid` and `sig` over canonical JSON of all fields above `signature`. |

**Entry fields:**

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Skill identifier. Matches `attestation.skill.name`. |
| `versions` | array of strings | Specific versions, or `["*"]` for all versions. |
| `revoked_at` | string | ISO 8601 UTC. When the revocation decision was made. |
| `reason` | string | Human-readable explanation. |
| `severity` | string | Severity level (e.g., `"critical"`, `"high"`, `"medium"`). |

**Signature computation:** The signature covers the canonical JSON (RFC 8785) serialization of the revocation list object with the `signature` field removed. The result is signed with Ed25519.

### 8.2 Revocation List Verification

Before trusting a revocation list, consumers MUST verify:

1. `schema_version` is supported.
2. `signature.keyid` exists in the consumer's trusted keys.
3. Ed25519 signature is valid over the canonical JSON of the list without the `signature` field.
4. `sequence_number` is positive.
5. `issued_at` < `expires_at` (accounting for clock skew tolerance).

### 8.3 Clock Skew Tolerance

All timestamp comparisons in revocation checking MUST apply a clock skew tolerance of **300 seconds (5 minutes)**. This prevents false failures on systems with slightly skewed clocks, which is common on VPS instances.

### 8.4 Install Context (Fail-Closed)

At install time, a valid and fresh revocation list is REQUIRED. The principle: refuse to install without confident knowledge of the revocation state.

| Condition | Result |
|-----------|--------|
| No revocation list provided | `E_REVOCATION_STALE` — reject installation. |
| List signature invalid | `E_REVOCATION_STALE` — reject installation. |
| List `expires_at` in the past (beyond skew tolerance) | `E_REVOCATION_STALE` — reject installation. |
| List `sequence_number` ≤ `cachedSequenceNumber` | `E_REVOCATION_STALE` — reject (possible rollback). |
| Skill found in `entries` (version match or `"*"`) | `E_REVOKED` — reject installation. |
| Skill not found in `entries` | Pass. `trustLevel: "full"`. |

### 8.5 Runtime Context (Fail-Open with Bounded Grace)

At runtime, revocation checking is lenient to avoid killing running agents due to transient infrastructure failures. Structured warnings provide machine-readable degraded trust signals.

| Condition | Result |
|-----------|--------|
| No revocation list available | `trustLevel: "degraded"`, warning `W_REVOCATION_UNAVAILABLE`. Check `lastValidRevocationList` for revocation entries before continuing. |
| List signature invalid | `trustLevel: "degraded"`, warning `W_REVOCATION_SIG_INVALID`. Fall back to `lastValidRevocationList` if available. |
| List expired, within grace period (24 hours + skew tolerance) | `trustLevel: "degraded"`, warning `W_REVOCATION_STALE`. Continue with the list. |
| List expired, beyond grace period | `trustLevel: "none"`, error `E_REVOCATION_STALE`. Stop the skill. |
| List `sequence_number` ≤ `cachedSequenceNumber` | Use `lastValidRevocationList` if available. Silent ignore (no warning). |
| Skill found in `entries` | `trustLevel: "none"`, error `E_REVOKED`. Disable immediately. |
| Skill not found in `entries`, list valid | `trustLevel: "full"`. |

**Runtime grace period:** 24 hours from `expires_at` (plus clock skew tolerance). This bounds the window during which a stale list is trusted.

### 8.6 lastValidRevocationList (Defense-in-Depth)

In runtime context, consumers MAY provide a `lastValidRevocationList` as a fallback. Before trusting it, the implementation MUST verify:

1. The list's signature is valid against `trustedKeys`.
2. The list is not expired beyond the runtime grace period.

If either check fails, the `lastValidRevocationList` MUST be discarded (treated as `undefined`). This prevents forged or stale fallback lists from being used to inject false revocations or suppress legitimate ones.

### 8.7 Revocation Matching

A skill matches a revocation entry when:

1. `entry.name` equals `attestation.skill.name` (exact string match).
2. `entry.versions` contains `attestation.skill.version` (exact string match) OR contains `"*"` (wildcard, matches all versions).

---

## 9. Filesystem Safety

These checks protect against attacks that exploit filesystem semantics.

| Threat | Mitigation | Error Code |
|--------|-----------|------------|
| **Symlink escape** | Reject any symbolic link found during recursive directory enumeration using `lstat`. | `E_SYMLINK` |
| **Hard link aliasing** | Reject regular files with `nlink > 1`. An attacker could hard-link a file outside the skill directory, causing the verifier to hash one version while the runtime reads another. Directories are exempt (directories commonly have `nlink > 2` due to `.` and `..`). `skipHardlinkCheck` is only honored when `context` is `"runtime"`. | `E_HARDLINK` |
| **Resource exhaustion** | Maximum 10,000 files per skill directory. Maximum 100 MB per individual file. Maximum 500 MB aggregate. | `E_LIMITS` |
| **Path traversal** | All file paths MUST resolve within the skill directory root. Paths containing `..` components that escape the root MUST be rejected. | `E_SYMLINK` or `E_INTEGRITY_MISMATCH` |
| **Extra file injection** | The integrity manifest is an allowlist. Any file in the skill directory (excluding `.vault/`) that is not listed in `integrity.files` causes verification failure. | `E_EXTRA_FILES` |

### 9.1 TOCTOU Considerations

The time-of-check-to-time-of-use (TOCTOU) gap between verification and execution is the caller's responsibility. Recommended mitigations:

1. **Copy-then-verify.** Copy the skill directory to an isolated location, verify the copy, execute from the copy.
2. **Read-only mount.** Verify the skill on a read-only filesystem mount.
3. **Container isolation.** Verify at container build time; the container image is immutable at runtime.

---

## 10. Security Considerations

### 10.1 Constant-Time Comparisons

All hash comparisons MUST use constant-time comparison (e.g., `crypto.timingSafeEqual` in Node.js). String comparison leaks information about how many bytes match, enabling timing attacks on integrity hashes.

Ed25519 verification functions in standard cryptographic libraries handle timing safety internally.

### 10.2 Signing Does Not Imply Safety

A valid signature proves that a specific key signed a specific set of bytes. It does NOT prove that the content is safe, well-written, or free of vulnerabilities. Signing establishes provenance and integrity, not quality.

Malicious publishers can generate valid key pairs and sign malicious skills. Consumers SHOULD combine signature verification with additional trust signals: publisher reputation, platform vetting, content analysis, and runtime sandboxing.

### 10.3 Key Management

Ed25519 private keys MUST be protected. Recommended practices:

- Store private keys in hardware security modules (HSMs) or platform secret managers.
- Use short-lived keys via Sigstore keyless signing (see Section 12) to eliminate long-term key storage.
- Rotate keys periodically and revoke compromised keys immediately.
- Derive key IDs deterministically from public key bytes to ensure consistency.

### 10.4 Canonicalizer Supply Chain

The RFC 8785 canonicalizer library is a critical dependency. If it produces different output for the same input, signatures will fail to verify. Implementations MUST:

- Pin the canonicalizer to an exact version (not a range).
- Include compatibility tests against RFC 8785 test vectors.
- Re-run compatibility tests before accepting library version bumps.

### 10.5 Schema Version as Security Boundary

Schema version checks are a security control, not a compatibility feature. An attacker who can introduce a future schema version might trigger parsing paths that the verifier has not been audited for. Unknown schema versions MUST be rejected immediately.

---

## 11. Extensibility

The format is designed for forward-compatible evolution without breaking existing implementations.

| Mechanism | Purpose |
|-----------|---------|
| `schema_version` in every file | Breaking changes require a version bump. Verifiers reject unknown versions. |
| Passthrough on all schemas | Unknown fields are preserved during parsing. New fields can be added without version bump. |
| `_critical` array in attestation | New fields that MUST be understood by verifiers, without requiring a version bump. |
| `skill.type` | New package types (`"skill.md"`, `"mcp"`, future types) without format changes. |
| `signatures[]` array | Dual-sign (publisher + platform) in future versions. |
| Hash string prefix | New algorithms (e.g., `sha384:`, `blake3:`) via new prefix. |
| `declared` passthrough in permissions | New capability categories without version bump. |

---

## 12. Sigstore Integration (Informative)

This section is informative, not normative. Ed25519 key pairs remain the baseline signing mechanism.

The DSSE envelope format used by this specification is directly compatible with Sigstore. Integration enables keyless signing:

1. Publisher authenticates via OIDC (GitHub, Google, etc.).
2. Sigstore Fulcio issues a short-lived certificate (typically 10 minutes) binding the OIDC identity to a signing key.
3. Publisher signs the attestation PAE with the ephemeral key.
4. Sigstore Rekor records the signature, certificate, and inclusion proof in an append-only transparency log.
5. The `signatures[].keyid` becomes the certificate fingerprint or OIDC subject.
6. At verification time, the consumer validates the signature against the certificate chain and verifies the Rekor inclusion proof.

Benefits:
- **No key management.** Publishers never generate, store, or rotate keys.
- **Identity-based trust.** Trust is tied to the publisher's GitHub/Google identity, not a raw key.
- **Transparency log.** Every signing event is publicly recorded, enabling after-the-fact forensics.
- **Compromise enumeration.** If a publisher's identity is compromised, all packages they signed can be enumerated by querying Rekor.

---

## 13. Well-Known Revocation Endpoint (Informative)

This section is informative. It defines a convention for registries and platforms that wish to distribute revocation lists automatically.

Registries SHOULD serve the current signed revocation list at:

```
https://<registry-domain>/.well-known/haldir-revocation.json
```

The response MUST be a valid `SignedRevocationList` as defined in Section 8.1.

Consumers SHOULD:
- Fetch the revocation list on every install operation.
- Cache the list locally with the `sequence_number` for rollback detection.
- Respect the `next_update` field as a polling interval hint.
- Fall back to the cached list if the fetch fails (runtime context only).

---

## 14. CLI Output Schema (Informative)

This section is informative. It defines a stable JSON output format for CLI tools implementing this specification.

```json
{
  "valid": true,
  "trustLevel": "full",
  "keyId": "publisher-key-2026",
  "warnings": [],
  "errors": [],
  "attestation": { "..." },
  "permissions": { "..." }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `valid` | boolean | Whether verification passed. |
| `trustLevel` | string | `"full"`, `"degraded"`, or `"none"`. |
| `keyId` | string or null | The key ID that verified, or null. |
| `warnings` | array | `[{ code, message }]` |
| `errors` | array | `[{ code, message, file? }]` |
| `attestation` | object or null | The verified attestation, or null. |
| `permissions` | object or null | The verified permissions, or null. |

**CLI exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Verification passed (`trustLevel` is `"full"` or `"degraded"`). |
| 1 | Verification failed (`trustLevel` is `"none"`). |
| 2 | Usage error (bad arguments, file not found). |

---

## 15. Conformance

### 15.1 Conforming Signer

A conforming signer MUST:
- Perform all filesystem safety checks (Section 9) before signing.
- Write `attestation.json` and `integrity.json` as canonical JSON (RFC 8785).
- Compute PAE per DSSE v1.0.0 over raw payload bytes.
- Include `integrity_hash` and `permissions_hash` in the attestation.
- Sign with Ed25519 (RFC 8032).

### 15.2 Conforming Verifier

A conforming verifier MUST:
- Implement all normative verification checks in the order specified in Section 7.2 (checks 1 through 25).
- Support both `install` and `runtime` contexts with their respective revocation policies.
- Use constant-time comparison for all hash verifications.
- Reject unknown schema versions.
- Check for and reject unrecognized `_critical` fields.
- Use RFC 8785 for canonical JSON parsing and comparison.
- Use DSSE v1.0.0 PAE construction for signature verification.
- Return structured output conforming to Section 7.4.

A conforming verifier MAY:
- Support Sigstore keyless verification (Section 12).
- Support additional hash algorithms identified by prefix (Section 4).
- Support additional `skill.type` values.
- Enforce permissions at runtime.

---

## Appendix A: JSON Schemas

Machine-readable JSON Schemas for all file formats are available in the `schemas/` directory of the specification repository.

## Appendix B: Test Vectors

The reference implementation repository provides:
- RFC 8785 canonicalization test vectors (numbers, unicode, escaping, key ordering).
- PAE construction test vectors.
- Ed25519 sign/verify round-trip vectors.
- Complete `.vault/` envelope fixtures (valid, tampered, unsigned, with symlink, with hard link, with extra file).
- Revocation list fixtures (valid, expired, rolled-back, forged signature).

## Appendix C: Acknowledgments

This specification builds on the work of the Secure Systems Lab (DSSE, in-toto), the Sigstore project (keyless signing, transparency logs), and the broader software supply chain security community. The CoSAI whitepaper on MCP security (January 2026) directly informed the revocation and trust model.

---

*Agent Skill Attestation Format (ASAF) v1.0-draft. Copyright 2026 Haldir Contributors. Licensed under Apache 2.0.*
