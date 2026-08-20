# swornmail (Rust)

Rust crate for the [SwornMail protocol](https://github.com/swornmail/spec):
cryptographic IPv6 prefix attestation for email senders.

Published as [`swornmail`](https://crates.io/crates/swornmail).

## Status

`0.0.1` publishes the protocol's wire-level constants and pins the crate
name while the draft stabilizes. `0.1` will implement token verification
against the shared test vectors
(`spec/test-vectors/v0.json`), matching the Go reference implementation
([swornmail-go](https://github.com/swornmail/swornmail-go)).

**The protocol wire format is not yet frozen** — expect breaking changes
before v1.

## Security

Report privately to security@swornmail.dev (see the spec repo's
`SECURITY.md`).

## License

Apache-2.0 (see `LICENSE`).
