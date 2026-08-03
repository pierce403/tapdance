# AGENTS.md — TapDance agent instructions

## Self-improvement directive

Update this file when a verified command, architectural rule, release pitfall, or collaboration
convention changes. Keep it concise and project-specific. Record useful failures as well as
successful procedures so the next agent does not repeat them.

## Operating context

The human collaborator prefers practical, direct work on `main` during early development.
Other agents may work concurrently, especially on GitHub Pages and `tapdance.ninja`. Always
re-read the current remote tip before publishing and use fast-forward-only updates. Preserve
unrelated concurrent changes.

## Responsibilities

- Keep the Android app buildable, testable, and honest about NFC outcomes.
- Preserve the one-shot safety boundary and never add automatic authentication retries.
- Maintain CI, versioned releases, checksums, provenance, and the static download site.
- Leave verified commands and non-obvious platform behavior documented here.

## Project overview

TapDance is a Java Android app that tests one all-zero factory `DataProtKey` against an
authorized NXP MIFARE Ultralight AES tag. Protocol code lives under
`app/src/main/java/tech/titor/tapdance/nfc`; Android lifecycle/UI code is in `MainActivity`;
the dependency-free Pages template is `site/index.html`.

## Non-negotiable safety boundaries

- No key recovery, dictionary search, brute force, tag emulation, or reader interaction.
- No memory-write commands and no Android `INTERNET` permission.
- Exactly one candidate-key proof per explicit arm action; never retry automatically.
- A failed proof may consume an `AUTH_LIM` attempt. Keep the confirmation warning visible.
- Only a valid returned `RndA` proof is **Accepted**. Android may hide a Type 2 NAK as
  `IOException`; report that as **Inconclusive**, not a proven rejection.
- Cancellation must be checked before every RF frame and close an active `NfcA` session.

## Build and test

Requires JDK 17 and the Android SDK:

```bash
./gradlew --no-daemon --stacktrace lintRelease testReleaseUnitTest assembleRelease
```

The NFC core and unit tests compile with strict Java warnings. GitHub Actions is the authoritative
full Android build environment when a local Android SDK or dependency downloads are unavailable.

## Release workflow

- Ordinary pushes and pull requests run `.github/workflows/ci.yml` only.
- A release requires changing **both** `VERSION` and `VERSION_CODE` in the same commit.
- `.github/workflows/android.yml` builds the exact release APK once, verifies its signature,
  hashes and attests it, then supplies byte-identical files to Releases and Pages.
- Alpha APKs use an ephemeral CI signing key. New alphas require uninstall/reinstall.
- The Pages source must be enabled as **GitHub Actions** in repository settings before the
  first deployment. The default workflow token cannot enable a new Pages site.

## Known pitfalls

- Gradle 8.11.1 requires the checked-in wrapper JAR SHA-256 `2db75c40782f5e8ba1fc278a5574bab070adccb2d21ca5a6e5ed840888448046`.
- Modern `apksigner --print-certs` labels the digest line `V2 Signer`, not always `Signer #1`;
  parse the suffix `certificate SHA-256 digest:` rather than a fixed prefix.
- Pixel/AOSP NFC often turns a four-bit Type 2 NAK into a generic Java `IOException`.
- AOSP deliberately recognizes that Type 2 NAK below the app API, reconnects the tag, and returns
  no payload; `NfcService` then maps the null result to a generic transceive failure. Keep such a
  proof-stage result **Inconclusive**, though a still-connected link may be described as strongly
  consistent with a hidden rejection.
- Diagnostic recording must be passive: record only existing frames, never retry, retain reports
  in memory, and warn before Android Sharesheet disclosure of UID, frames, or device build data.
- Target SDK 35 enforces edge-to-edge; preserve the system-bar inset handling.

## Style and tooling

Prefer small, inspectable changes and primary protocol/platform sources. Keep the app and site
dependency-light, local-first, accessible, and explicit about trade-offs. These conventions
adapt the useful repository-etiquette ideas from <https://recurse.bot> to TapDance.
