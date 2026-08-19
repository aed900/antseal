# Release signing

How antseal releases are signed, how anyone checks one, and how the signing key
is looked after.

The mechanism is decided by
[D71](../decisions/D71-binary-signing-mechanism-and-key-custody.md) — one
long-lived Ed25519 keypair held by the maintainer, used with
[minisign](https://jedisct1.github.io/minisign/), signing performed locally. The
release channel is decided by
[D72](../decisions/D72-release-targets-distribution-and-crates-io-scope.md).

| document | audience | what it covers |
|---|---|---|
| [`verifying-a-release.md`](verifying-a-release.md) | anyone who downloaded a release | the command to run, how to read its output, where to get the key, and what a green result does and does not mean |
| [`key-custody.md`](key-custody.md) | maintainer, reviewers | holder, backups, loss, rotation, compromise response, and the fact that a key cannot be withdrawn. Append-only |
| [`maintainer-key-procedure.md`](maintainer-key-procedure.md) | maintainer only | the exact commands for the acts nobody else can perform: generating the key, the registrar `TXT` record, the timestamp anchor, and the tool pin |

Two scripts implement the machine halves:

- `scripts/sign-release.sh` — builds `SHA256SUMS` and signs it and every
  artifact, with the structured trusted comment D71 §2 R4 requires. Refuses an
  unencrypted key.
- `scripts/verify-release.sh` — checks a downloaded directory by exact
  trusted-comment equality, the only form D71 §2 R3 permits a gate to use.
  `--self-test` plants every mutation D71 §1.3 measured and asserts each is
  caught by its own distinct failure.

> **What has and has not actually been run is recorded in exactly one place:**
> [`maintainer-key-procedure.md`](maintainer-key-procedure.md) §7. No other page
> in this directory states it, so no other page goes stale when the maintainer
> takes an act.
