# Security policy

## Report a vulnerability

Please use GitHub's private vulnerability reporting feature for this repository. Do not put
sensitive tag data, access-system details, or an unpatched exploit in a public issue.

## NFC safety boundary

TapDance sends one candidate-key authentication only after the user explicitly arms a scan.
It has no key dictionary, retry loop, tag-emulation path, memory-write command, Internet
permission, telemetry SDK, or persistent NFC storage.

A rejected authentication may still advance the tag's configured `AUTH_LIM` counter. The
current counter value cannot be read, and reaching its threshold can permanently prevent
authentication to protected data. Treat every arm action as potentially consuming one
remaining attempt.

Only a valid returned `RndA` proof is reported as **Accepted**. Android NFC controllers often
surface a Type 2 Tag NAK as a generic `IOException`; TapDance reports that case as
**Inconclusive**, never retries it, and does not claim that the key was cryptographically
rejected.

## Alpha APK signing

The alpha package ID is `tech.titor.tapdance.alpha`. GitHub Actions signs each release with an
ephemeral, build-specific key. No reusable private signing credential is published or stored in
the repository.

This means a newer alpha cannot update an older alpha in place: uninstall the old app before
installing the new APK. TapDance stores no app data, so that uninstall has no migration cost.
The build-specific signer does **not** prove publisher identity. Verify the APK against its
SHA-256 checksum and the repository's GitHub build-provenance attestation.

Any future production package must use a different application ID and a private, offline-
generated signing key from its first release.
