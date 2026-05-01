# Safety model

Foundation enforces read-only by default through three concentric layers.

## Layer 1: Client-layer enforcement

`sophos.Client.Do` and `sophos.Client.DoRaw` intercept all outbound XML and run
`safety.IsMutating(xml)` before dispatch. If the active profile sets `readOnly: true`
and the XML contains mutating verbs (`<Set …>`, `<Remove …>`), the client returns
`ErrReadOnlyViolation` with the list of detected verbs.

This layer catches bugs in higher-level code that forget the gate.

## Layer 2: Service-layer enforcement

`svc.Raw.PreviewRequest` is the only foundation-phase code path accepting user-supplied
XML. It runs `safety.IsMutating` first and returns `Preview{Mutating: true, Verbs: […],
Redacted: <xml>}`. The CLI prints a warning and the redacted XML when mutating verbs are
detected.

**There is no apply path in foundation.** A `--yes` flag exists for forward-compatibility,
but it always returns `unsupported_in_phase`. The apply path lands deliberately in Phase 6
alongside full diff/preview/apply workflows.

## Layer 3: Integration-test gate

`internal/testutil.IntegrationClient` (enabled via `SOPHOSFW_INTEGRATION=1`) is hardcoded
to read-only mode regardless of profile setting. Any test constructing a mutating envelope
panics at construction time, not send time. The "no mutations against production" guarantee
is mechanical, not convention.

## Credential redaction

`safety.RedactXML(xml []byte) []byte` rewrites `<Username>` and `<Password>` tags to
`***` before any log, error message, dry-run printout, or test fixture. Raw credential
bytes never leave `client.Do`. Debug output is always redacted.

`safety.RedactString` handles non-XML log lines mentioning credentials.

**Guarantee:** Credentials never appear in any output — logs, errors, debug, tests, or
stdout. This is verified by assertion in test coverage.

## Reference

See the full specification at
`docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md` (section 4).
