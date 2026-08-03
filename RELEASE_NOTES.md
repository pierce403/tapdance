# TapDance 0.1 alpha

The first working TapDance release provides a one-shot Android test for the all-zero factory
`DataProtKey` on NXP MIFARE Ultralight AES tags.

Highlights:

- Exact MF0AES(H)20 `GET_VERSION` recognition
- Full AES-128 mutual authentication using NXP's documented flow
- One explicit attempt with no automatic retry and no memory-write commands
- Honest handling of Android NFC controllers that hide short NAK responses
- No Internet permission, analytics, telemetry, or persistent NFC data
- Official NXP cryptographic vectors and negative-path unit tests
- SHA-256 checksum and GitHub build-provenance attestation

This is an alpha utility. A failed authentication can advance a tag's configured `AUTH_LIM`
counter. Use it only with tags you own or are explicitly authorized to test, and do not repeat
an inconclusive test blindly.

The APK uses a build-specific ephemeral alpha signing key. Future alphas require uninstalling
the prior version before installation. Verify the release checksum and provenance; see
`SECURITY.md` for the signing model.
