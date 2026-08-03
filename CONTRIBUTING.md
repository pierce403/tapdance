# Contributing

Keep TapDance narrow, inspectable, and conservative.

Before opening a change:

1. Do not add key recovery, brute force, tag emulation, memory writes, reader interaction,
   analytics, advertising, telemetry, or Internet access.
2. Preserve the explicit one-shot arm step and never retry authentication automatically.
3. Keep protocol and cryptographic code independent of Android where possible.
4. Add or update deterministic tests for every protocol change.
5. Run `./gradlew lintRelease testReleaseUnitTest assembleRelease`.

Security-sensitive behavior changes should cite the relevant primary specification or Android
platform source in the pull request.
