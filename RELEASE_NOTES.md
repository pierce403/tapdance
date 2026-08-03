# TapDance 0.1.0-alpha.3

This alpha adds a deeper, still one-shot diagnostic for the ambiguous final-stage failures that
stock Android can produce while testing the all-zero factory `DataProtKey` on NXP MIFARE
Ultralight AES tags.

Highlights:

- Exact MF0AES(H)20 `GET_VERSION` recognition
- Full AES-128 mutual authentication using NXP's documented flow
- One explicit attempt with no automatic retry and no memory-write commands
- Memory-only exchange trace with phase, Android-exposed frames, timing, and exception details
- NFC-A metadata including ATQA, SAK, tech list, timeout, frame limit, and post-exchange link state
- Honest identification of proof-stage failures strongly consistent with Android-hidden NAKs,
  while preserving the formal **Inconclusive** result
- Separate RF tag-loss interpretation
- Selectable diagnostic report with deliberate copy and share actions plus a disclosure warning
- Optional Pixel NFC controller-log guidance for a deeper one-shot capture
- No Internet permission, analytics, telemetry, or persistent NFC data
- Official NXP cryptographic vectors plus exchange-recorder and report-classification tests
- SHA-256 checksum and GitHub build-provenance attestation

This is an alpha utility. A failed authentication can advance a tag's configured `AUTH_LIM`
counter. Use it only with tags you own or are explicitly authorized to test, and do not repeat
an inconclusive test blindly.

The APK uses a build-specific ephemeral alpha signing key. Future alphas require uninstalling
the prior version before installation. Verify the release checksum and provenance; see
`SECURITY.md` for the signing model.
