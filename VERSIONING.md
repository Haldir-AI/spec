# Versioning & Conformance

## Version Format

ASAF uses semantic versioning: `MAJOR.MINOR.PATCH[-status]`

- **MAJOR:** Breaking changes to the envelope format or verification contract
- **MINOR:** Backward-compatible additions (new optional fields, new error codes)
- **PATCH:** Non-normative clarifications, typo fixes
- **Status:** `draft` | `rc1` | `rc2` | ... | (none for stable)

**Current version:** 1.0-draft

## What "draft" Means

- The format is implemented and reviewed, but not yet frozen
- Breaking changes are possible before v1.0 stable
- Implementers should track the spec repo for updates
- Feedback via issues is strongly encouraged

## Conformance Testing

A reference test suite is planned for v1.0 stable. Until then:
- The [Haldir reference implementation](https://github.com/haldir-ai/haldir) has 122 tests covering all 25 verification checks
- Independent implementations SHOULD verify compatibility against Haldir's test fixtures in `fixtures/`

## Breaking Change Process

1. **Breaking change proposed** via issue with rationale
2. **Discussion period** (minimum 14 days for community feedback)
3. **Draft PR** with spec edits, examples, and migration guide
4. **Approval requires** demonstrated need:
   - Security fix, or
   - Adoption blocker (spec is unimplementable), or
   - Spec ambiguity causing divergent implementations
5. **MAJOR version bump** in both spec and reference implementation
6. **CHANGELOG entry** with migration path
7. **Announcement** in discussions and README

Breaking changes are avoided when possible. Additive changes (new optional fields, new error codes) use MINOR bumps.

## Relationship to Reference Implementation

- **This spec** defines the normative format
- **Haldir** is the reference implementation
- Version alignment: ASAF 1.0.x maps to Haldir 1.0.x
- JSON Schemas are generated from Haldir's Zod schemas and copied here
- CI validates spec schemas against Haldir's test fixtures

## Conformance Levels

A **conforming verifier** MUST:
- Implement all 25 verification checks in order (see SPEC.md Section 7.2)
- Support both `install` and `runtime` contexts
- Use constant-time hash comparison
- Reject unknown schema versions
- Check `_critical` fields
- Use RFC 8785 canonical JSON
- Use DSSE v1.0.0 PAE construction

A **conforming signer** MUST:
- Perform filesystem safety checks before signing
- Write attestation and integrity as canonical JSON
- Compute PAE correctly
- Include both `integrity_hash` and `permissions_hash`
- Sign with Ed25519

## Spec Evolution Guarantee

Once v1.0 stable is released:
- v1.x releases are backward-compatible (verifiers can verify v1.0 envelopes)
- v2.0 may introduce breaking changes, but v1.x support remains in Haldir for 1 year minimum
- Deprecation warnings precede breaking changes by at least 6 months
