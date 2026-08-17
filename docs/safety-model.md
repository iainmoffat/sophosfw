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

## Snapshot filenames must be injective

`draft.Slug` is deliberately lossy: it lowercases, folds every run of
non-alphanumerics to a single `-`, and trims the ends. It is therefore **not
injective** — `*.foo.com`, `foo.com`, `foo com` and `foo/com` all reduce to
`foo-com`. Sophos names routinely differ only in that punctuation: wildcard
FQDN objects live alongside their bare siblings on any real device.

`backup` must not let two objects share a file. It assigns filenames in two
passes: names whose slug is unique keep the readable stem, and every member
of a colliding set gets a short content hash appended. Disambiguating *all*
colliders rather than just the later ones keeps the mapping independent of
the order the device returned records in.

Filenames are only a convenience — `loadSnapshotRecords` keys on the `Name`
field stored *inside* each file, so they must be unique but need not be
reversible or stable.

Two checks back this up, and both are the kind that catch the bug from
inside the tool:

- **A filename claimed twice in one run is an error**, not an overwrite.
  Silent overwrite is what turns "one object missing" into "a phantom
  `added` in every future drift run".
- **Records written must equal files on disk**, per type, or the backup
  fails. The original bug reported `581 records` into a 578-file directory
  and nothing compared the two.

The invariant worth protecting is **`drift` against a freshly taken snapshot
reports zero deltas**. Anything the snapshot loses surfaces there as a
permanent false positive, and false positives train operators to skim the
one surface that tells them what changed on the firewall.

> `draft.Slug` is also used for draft paths (`DraftPath`), which have the
> same theoretical collision. Two rules whose names differ only in
> punctuation would share a draft file. Not addressed here: drafts are
> user-named, created one at a time, and carry the rule name inside the
> file.

## Reference

See the full specification at
`docs/superpowers/specs/2026-04-30-sophosfw-foundation-design.md` (section 4).
