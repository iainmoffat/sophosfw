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

## Decode fidelity: repeated elements

Sophos represents group membership as repeated sibling elements:

```xml
<FQDNHostList>
  <FQDNHost>a.example.org</FQDNHost>
  <FQDNHost>b.example.org</FQDNHost>
</FQDNHostList>
```

`xmlFragmentToMap` accumulates repeats into a slice. The decoded shape is
**scalar-or-slice**: a one-member list decodes as a bare string, two or more
decode as an array, in document order. Consumers reading a list-valued key
must handle both. The write side (`svc.marshalObjectBody`) already emits
`[]any` as flat repetition, so a record read from the device, edited, and
written back round-trips exactly.

This matters beyond cosmetics because group updates use **replace**
semantics. A decoder that dropped repeats would make the ordinary
read-modify-write flow destructive: the write body would carry only the
members that survived the read, silently evicting the rest. It would also
make `_diffHash` unsound (the hash would cover only part of the record, so
`--expected-diff-hash` could pass against a substantially edited object),
give `drift` a confidently wrong diff, cause `object usage` to under-report
references, and cause `backup` to persist an unrestorable snapshot.

**Regression tests must use fixtures with more than one member.** A
single-member fixture passes under both a correct and a truncating decoder,
which is how this class of bug hides. See
`testdata/sophos/responses/fqdnhostgroup_get_multi.xml`.

> **Snapshots taken before this fix are untrustworthy.** Any backup written
> by an earlier build recorded groups truncated to a single member. Re-take
> snapshots before relying on them for restore or drift comparison; the first
> `drift` run against an old snapshot will report every multi-member group as
> `modified`, which reflects the old snapshot's corruption, not device drift.

## Reference

See the full specification at
`docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md` (section 4).
