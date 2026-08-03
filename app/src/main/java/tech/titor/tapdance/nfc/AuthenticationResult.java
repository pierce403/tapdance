package tech.titor.tapdance.nfc;

import java.util.Arrays;

public final class AuthenticationResult {
    public enum Outcome {
        ACCEPTED,
        REJECTED,
        INCONCLUSIVE,
        UNSUPPORTED
    }

    private final Outcome outcome;
    private final String detail;
    private final byte[] uid;
    private final byte[] version;

    private AuthenticationResult(Outcome outcome, String detail, byte[] uid, byte[] version) {
        this.outcome = outcome;
        this.detail = detail;
        this.uid = uid == null ? new byte[0] : Arrays.copyOf(uid, uid.length);
        this.version = version == null ? new byte[0] : Arrays.copyOf(version, version.length);
    }

    public static AuthenticationResult of(
            Outcome outcome, String detail, byte[] uid, byte[] version) {
        return new AuthenticationResult(outcome, detail, uid, version);
    }

    public Outcome outcome() {
        return outcome;
    }

    public String detail() {
        return detail;
    }

    public byte[] uid() {
        return Arrays.copyOf(uid, uid.length);
    }

    public byte[] version() {
        return Arrays.copyOf(version, version.length);
    }
}

