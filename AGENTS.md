# AGENTS.md — sophosfw

## Operating rules
- Treat the Sophos API as production. Default to read-only.
- Never log unredacted credentials. Use `safety.RedactXML` first.
- Mutating commands are not implemented in foundation phase. Do not add them
  outside a Phase-6 spec.
- Integration tests must round-trip through `internal/testutil.IntegrationClient`
  which mechanically blocks mutations. Do not add integration tests that bypass it.

## Where to look
- Spec: `docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md`
- Plan: `docs/superpowers/plans/2026-04-30-sophosfw-foundation.md`
- Roadmap (Phases 3-7): `docs/roadmap.md`
- Agent skill: `.claude/skills/sophos-firewall/SKILL.md`

## Conventions
- Cobra commands in `internal/cli/`; thin — they call into `internal/svc`.
- Service layer is the only home for read-only enforcement and dry-run gating.
- Catalog is the seam for adding new XML tags. YAML metadata + optional Go-typed parser.
- JSON envelope schema names follow `sophosfw.v1.<name>`.
