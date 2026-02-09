# Agent Skill Attestation Format (ASAF)

**Version:** 1.0-draft
**Status:** Draft
**License:** Apache 2.0

This repository contains the specification for the Agent Skill Attestation Format (ASAF), a framework-agnostic format for cryptographically signing, verifying, and revoking AI agent skills and MCP servers.

📖 **[Read the specification](SPEC.md)**

## What This Solves

No major agent registry implements cryptographic signing at the skill package level. ASAF provides:

- **Tamper-evident integrity** via SHA-256 allowlists
- **Publisher authentication** via Ed25519 signatures (DSSE v1.0.0)
- **Signed revocation** with fail-closed install and fail-open runtime modes
- **Sigstore compatibility** for keyless signing and transparency logs

## Reference Implementation

- **[haldir](https://github.com/haldir-ai/haldir)** — TypeScript reference implementation
- **[sign-action](https://github.com/haldir-ai/sign-action)** — GitHub Action for CI signing *(coming soon)*

## JSON Schemas

Machine-readable JSON Schemas (JSON Schema Draft 2020-12) are provided in the `schemas/` directory. These schemas are automatically generated from the Zod schemas in the [Haldir reference implementation](https://github.com/haldir-ai/haldir).

To validate a `.vault/` envelope against the schemas:

```bash
npm install -g ajv-cli
ajv validate -s schemas/signature.schema.json -d path/to/.vault/signature.json
```

Schema updates are synchronized with Haldir releases. If the schemas in this repo diverge from Haldir, CI will fail.

## Status

This spec is in **draft** status (v1.0-draft). The format is implemented and reviewed, but not yet frozen. Breaking changes are possible before v1.0 stable. Feedback welcome via issues.

See [VERSIONING.md](VERSIONING.md) for details on the versioning and breaking change process.

## Contributing

See [CONTRIBUTING.md](https://github.com/haldir-ai/.github/blob/main/CONTRIBUTING.md) in the org-level repo.

## License

Apache 2.0. See [LICENSE](LICENSE).
