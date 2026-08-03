# TapDance

TapDance is a deliberately narrow Android NFC diagnostic. It tests whether an authorized
NXP MIFARE Ultralight AES tag accepts the all-zero factory `DataProtKey` by making one
explicit mutual-authentication attempt.

It does **not** recover keys, clone credentials, emulate tags, test door readers, or write
tag memory.

## Install

Download the APK and its SHA-256 checksum from the latest GitHub Release or the project's
GitHub Pages download page. Android 8.0 (API 26) or newer and NFC-A support are required.

This is an alpha build distributed outside the Play Store. Android may ask you to allow
installs from your browser or file manager; grant that permission only for the installation,
then turn it off again.

Each alpha release uses an ephemeral CI signing key. To install a newer alpha, uninstall the
older one first; Android will not accept it as an in-place update. TapDance stores no app data.

## Use

1. Open TapDance and read the visible attempt-counter warning.
2. Tap **Arm one-shot test**.
3. Hold a tag you own or are explicitly authorized to test against the phone.
4. Read the result:
   - **Accepted** proves that the tag completed mutual authentication with the factory key.
   - **Rejected** means Android exposed an explicit NFC rejection.
   - **Inconclusive** means no valid proof was returned. Some Android NFC stacks hide a tag's
     short NAK response as a generic I/O failure, so TapDance does not turn that into a false
     cryptographic claim.

TapDance never retries automatically. A failed authentication can still advance a tag's
configured `AUTH_LIM` counter; at its threshold, protected data may become permanently
unauthenticatable. Do not repeat the test blindly.

## Technical scope

TapDance accepts only the exact documented `GET_VERSION` signatures for MF0AES(H)20 tags,
then tests key number `00` (`DataProtKey`) with AES-128-CBC and fresh zero IVs for each RF
message:

```text
60 → version
1A 00 → AF || E(RndB)
AF || E(RndA || rotate(RndB)) → 00 || E(rotate(RndA))
```

Android's `NfcA` layer adds and checks Type 2 Tag CRC bytes. The app sends no read-memory or
write-memory command. The manifest intentionally contains no `INTERNET` permission.

Protocol references:

- [NXP MF0AES(H)20 data sheet](https://www.nxp.com/docs/en/data-sheet/MF0AES%28H%2920.pdf)
- [NXP AN13452 authentication example](https://www.nxp.com/docs/en/application-note/AN13452.pdf)
- [Android `NfcA` API](https://developer.android.com/reference/android/nfc/tech/NfcA)

## Build and test

Requirements: JDK 17 and the Android SDK.

```bash
./gradlew --no-daemon lintRelease testReleaseUnitTest assembleRelease
```

The unit tests replay the official NXP authentication vector and cover explicit rejection,
Android-hidden NAK/I/O failure, altered proofs, malformed frames, and target-chip rejection.

GitHub Actions runs lint, tests, and a release build on every push and pull request. A trusted
push to `main` that changes `VERSION` or `VERSION_CODE` also publishes a checksummed APK,
build-provenance attestation, GitHub Release, and GitHub Pages artifact. Release changes must
bump both files; ordinary code and documentation pushes run CI without mutating a release.

## Security and authorization

Use TapDance only on tags you own or have explicit permission to test. Read
[SECURITY.md](SECURITY.md) for the build-specific alpha-signing model and vulnerability-
reporting guidance.

MIT licensed. TapDance is independent and is not affiliated with NXP, Flipper Devices, or any
access-control vendor.
