# swornmail (Rust)

Rust crate for the [SwornMail protocol](https://github.com/swornmail/spec):
cryptographic IPv6 prefix attestation for email senders.

Published as [`swornmail`](https://crates.io/crates/swornmail).

## Status

`0.2`: token verification against the shared v1 vectors. Mode-2 tokens
(tagged `COSE_Sign1` over a CBOR payload) and operator key/policy records
are verified and parsed per `draft-kafedzhy-swornmail-01`. The staged API
runs all local checks, authorizes the signed prefix against the policy, and
only then permits key verification; signing is not implemented.
The ordinary `verify` helper requires both the key and policy; the explicitly
named `verify_signature_only` primitive exists only for frozen-vector tooling
and is not a complete protocol verdict.

`verify` returns an `Outcome`, not a `Verified`: an observe-only (`t=y`)
operator is a separate variant, so it is not possible to read a testing
deployment as `sworn=pass` without noticing. Key reputation on
`Verified::observed_unit` (the source `/64` this connection corroborated), not
on `Verified::unit` (the aggregation the operator asked for).

`0.2` is a breaking API change from `0.1`: `verify` takes a policy record,
returns `Outcome`, and `Verified` carries the observed unit.

It also tightens which *records* parse, within the same `-01` wire format.
Token bytes are unchanged and every pre-existing conformance vector still
passes byte-identically, but three record shapes `0.1` accepted are now
malformed: a policy `u=` coarser than any prefix in the same record, a `rua=`
outside a conservative ASCII `mailto:<dot-atom>@<domain>`, and any octet
outside printable US-ASCII anywhere in a record. Each closed a way for two
conforming verifiers to read one record differently — the last of those was
a measured three-way disagreement between this crate, the Go reference and
the rspamd module over what counts as whitespace.

This is an **independent** implementation, written from the draft rather
than ported from the Go reference implementation
([swornmail-go](https://github.com/swornmail/swornmail-go)). Both verify
against the same file, `test-vectors/v1.json` in the specification
repository, which is the cross-implementation freeze gate.

The `-01` wire format and v1 conformance vectors are frozen. Library APIs may
still change before crate v1.0, but wire changes require a new protocol
revision and vector set.

## Testing

`cargo test` resolves the vectors from `$SWORN_VECTORS`, then a sibling
`swornmail-spec` checkout, then the vendored snapshot in
`tests/testdata/v1.json`. When the sibling checkout is present, the tests
also assert that the snapshot has not drifted from it.

## Security

Report privately to security@swornmail.dev (see the spec repo's
`SECURITY.md`).

## License

Apache-2.0 (see `LICENSE`).

Maintained by Val Kafedzhy. Copyright:
see `NOTICE`.
