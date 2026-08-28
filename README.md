# swornmail (Rust)

Rust crate for the [SwornMail protocol](https://github.com/swornmail/spec):
cryptographic IPv6 prefix attestation for email senders.

Published as [`swornmail`](https://crates.io/crates/swornmail).

## Status

`0.1`: token verification against the shared v1 vectors. Mode-2 tokens
(tagged `COSE_Sign1` over a CBOR payload) and operator key/policy records
are verified and parsed per `draft-kafedzhy-swornmail-01`; signing is not
implemented.

This is an **independent** implementation, written from the draft rather
than ported from the Go reference implementation
([swornmail-go](https://github.com/swornmail/swornmail-go)). Both verify
against the same file, `test-vectors/v1.json` in the specification
repository, which is the cross-implementation freeze gate.

**The protocol wire format is not yet frozen** — expect breaking changes
before v1.

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
