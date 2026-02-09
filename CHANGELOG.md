# Changelog

All notable changes to ASAF (Agent Skill Attestation Format) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0-draft] - 2026-02-09

### Added

- Initial specification release
- 15 sections covering envelope format, signing, verification, revocation
- 25-check verification contract with fail-fast semantics
- DSSE v1.0.0 signature envelope format
- Ed25519 digital signatures (RFC 8032)
- RFC 8785 canonical JSON for deterministic serialization
- SHA-256 integrity allowlists
- Signed revocation with fail-closed install / fail-open runtime modes
- Permission declarations (informational, not enforced in v1.0)
- Filesystem safety checks (symlink, hard link, path traversal)
- Multi-signature support for dual-sign scenarios
- JSON Schemas for all envelope files (Draft 2020-12)
- Sigstore integration guidance (informative)
- Well-known revocation endpoint convention
- CLI output schema for tool interoperability
- Conformance requirements for signers and verifiers

### Security

- Check 17: attestation.json on disk must match signed payload (prevents replacement attacks)
- Check 24: permissions_hash verification (tamper-evident permission declarations)
- Defense-in-depth: lastValidRevocationList signature verification before use
- Freshness gate: expired revocation lists beyond grace period are rejected
- Constant-time hash comparisons to prevent timing attacks

[Unreleased]: https://github.com/haldir-ai/spec/compare/v1.0-draft...HEAD
[1.0-draft]: https://github.com/haldir-ai/spec/releases/tag/v1.0-draft
