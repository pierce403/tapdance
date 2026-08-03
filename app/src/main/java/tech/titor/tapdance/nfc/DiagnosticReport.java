package tech.titor.tapdance.nfc;

import java.util.Locale;

/** Human-readable, memory-only report for one explicitly armed test. */
public final class DiagnosticReport {
    public static final class Metadata {
        public String appVersion = "";
        public String device = "";
        public String androidVersion = "";
        public String buildFingerprint = "";
        public String[] technologies = new String[0];
        public byte[] atqa = new byte[0];
        public int sak;
        public int maxTransceiveLength;
        public int timeoutMillis;
        public int presenceCheckDelayMillis;
        public boolean connectedAfterExchange;
        public boolean cancelledDuringExchange;
        public long totalDurationNanos;
        public String sessionErrorType = "";
        public String sessionErrorMessage = "";
    }

    private final String summary;
    private final String full;

    private DiagnosticReport(String summary, String full) {
        this.summary = summary;
        this.full = full;
    }

    public static DiagnosticReport create(
            AuthenticationResult result,
            RecordingByteTransceiver trace,
            Metadata metadata) {
        RecordingByteTransceiver.Exchange terminal = terminalExchange(trace);
        int proofCount = trace.proofSubmissionCount();
        String terminalPhase = terminal == null ? "CONNECT" : terminal.phase().name();
        String finalIo = finalIo(terminal, metadata);
        String interpretation = interpretation(result, terminal, metadata, proofCount);

        StringBuilder compact = new StringBuilder();
        compact.append("PHASE  ").append(terminalPhase);
        compact.append("\nPROOF  ").append(proofStatus(proofCount));
        compact.append("\nFINAL  ").append(finalIo);
        compact.append("\nLINK   ").append(
                metadata.connectedAfterExchange ? "CONNECTED AFTER EXCHANGE" : "NOT CONNECTED");
        compact.append("\nCANCEL ").append(
                metadata.cancelledDuringExchange ? "SESSION CLOSE REQUESTED" : "NO");
        compact.append("\nTIME   ").append(formatDuration(metadata.totalDurationNanos));

        StringBuilder report = new StringBuilder();
        report.append("TapDance diagnostic report\n");
        report.append("==========================\n");
        line(report, "APP", metadata.appVersion);
        line(report, "OUTCOME", result.outcome().name());
        line(report, "DETAIL", result.detail());
        line(report, "UID", Hex.encodeSpaced(result.uid()));
        line(report, "VERSION", Hex.encodeSpaced(result.version()));
        line(report, "TERMINAL_PHASE", terminalPhase);
        line(report, "PROOF_SUBMISSIONS", proofReportStatus(proofCount));
        line(report, "FINAL_IO", finalIo);
        line(report, "CONNECTED_AFTER", Boolean.toString(metadata.connectedAfterExchange));
        line(report, "CANCELLED_DURING", Boolean.toString(metadata.cancelledDuringExchange));
        line(report, "TOTAL_TIME", formatDuration(metadata.totalDurationNanos));
        line(report, "INTERPRETATION", interpretation);
        report.append('\n');
        line(report, "ATQA", Hex.encodeSpaced(metadata.atqa));
        line(report, "SAK", String.format(Locale.US, "%02X", metadata.sak & 0xFF));
        line(report, "TECH", join(metadata.technologies));
        line(report, "MAX_TRANSCEIVE", metadata.maxTransceiveLength + " bytes");
        line(report, "TIMEOUT", metadata.timeoutMillis + " ms");
        line(report, "PRESENCE_DELAY", metadata.presenceCheckDelayMillis + " ms");
        line(report, "DEVICE", metadata.device);
        line(report, "ANDROID", metadata.androidVersion);
        line(report, "BUILD", metadata.buildFingerprint);
        if (!metadata.sessionErrorType.isEmpty()) {
            line(report, "SESSION_ERROR", shortType(metadata.sessionErrorType)
                    + messageSuffix(metadata.sessionErrorMessage));
        }

        report.append("\nEXCHANGES\n");
        if (trace.exchanges().isEmpty()) {
            report.append("(none)\n");
        }
        for (RecordingByteTransceiver.Exchange exchange : trace.exchanges()) {
            report.append(String.format(
                    Locale.US,
                    "[%s +%s] TX %s\n",
                    exchange.phase().name(),
                    formatDuration(exchange.offsetNanos()),
                    Hex.encodeSpaced(exchange.command())));
            if (exchange.failed()) {
                report.append("  ERR ")
                        .append(shortType(exchange.errorType()))
                        .append(messageSuffix(exchange.errorMessage()))
                        .append(" after ")
                        .append(formatDuration(exchange.durationNanos()))
                        .append('\n');
            } else {
                report.append("  RX  ")
                        .append(Hex.encodeSpaced(exchange.response()))
                        .append(" after ")
                        .append(formatDuration(exchange.durationNanos()))
                        .append('\n');
            }
        }

        report.append("\nNOTES\n");
        report.append("- Android NfcA adds/checks CRC; CRC and parity are not exposed here.\n");
        report.append("- Stock Android may deliberately turn a Type-2 four-bit NAK into ")
                .append("IOException(\"Transceive failed\").\n");
        report.append("- The report contains no decrypted random values, keys, or tag-memory data.\n");
        if (hasRepeatedPhase(trace)) {
            report.append("- WARNING: the recorder observed a repeated protocol phase.\n");
        } else {
            report.append("- The recorder observed no repeated protocol phase.\n");
        }
        report.append("- TapDance sent no memory-write command.\n");
        report.append("\nDEEPER CAPTURE (OPTIONAL)\n");
        report.append("On supported Pixels, enable Developer options for NFC stack debug logs, ")
                .append("NFC verbose vendor logs, and unfiltered NFC NCI logs; reboot, perform ")
                .append("one armed test, then take an Android bug report. Such captures may ")
                .append("contain sensitive nearby NFC traffic.\n");

        return new DiagnosticReport(compact.toString(), report.toString());
    }

    public String summary() {
        return summary;
    }

    public String full() {
        return full;
    }

    private static RecordingByteTransceiver.Exchange terminalExchange(
            RecordingByteTransceiver trace) {
        if (trace.exchanges().isEmpty()) return null;
        return trace.exchanges().get(trace.exchanges().size() - 1);
    }

    private static String finalIo(
            RecordingByteTransceiver.Exchange terminal, Metadata metadata) {
        if (terminal != null) {
            if (terminal.failed()) {
                return shortType(terminal.errorType())
                        + messageSuffix(terminal.errorMessage())
                        + " / "
                        + formatDuration(terminal.durationNanos());
            }
            return terminal.response().length + " response bytes / "
                    + formatDuration(terminal.durationNanos());
        }
        if (!metadata.sessionErrorType.isEmpty()) {
            return shortType(metadata.sessionErrorType)
                    + messageSuffix(metadata.sessionErrorMessage);
        }
        return "no exchange";
    }

    private static String interpretation(
            AuthenticationResult result,
            RecordingByteTransceiver.Exchange terminal,
            Metadata metadata,
            int proofCount) {
        if (proofCount > 1) {
            return "SAFETY VIOLATION: the recorder observed more than one candidate-key proof.";
        }
        if (terminal != null
                && terminal.phase() == RecordingByteTransceiver.Phase.AUTH_PROOF
                && metadata.cancelledDuringExchange
                && terminal.failed()) {
            return "The app closed the NFC session during the proof exchange; this says nothing "
                    + "reliable about the key.";
        }
        if (result.outcome() == AuthenticationResult.Outcome.ACCEPTED) {
            return "The returned RndA proof verified with the factory key.";
        }
        if (result.outcome() == AuthenticationResult.Outcome.REJECTED) {
            return "Android exposed an explicit card rejection.";
        }
        if (terminal == null || terminal.phase() != RecordingByteTransceiver.Phase.AUTH_PROOF) {
            return "The exchange ended before a candidate-key proof completed.";
        }
        if (terminal.errorType().endsWith("TagLostException")) {
            return "Android reported RF tag loss; this says nothing reliable about the key.";
        }
        if (terminal.failed()
                && terminal.errorType().endsWith("IOException")
                && "Transceive failed".equalsIgnoreCase(terminal.errorMessage())) {
            return metadata.connectedAfterExchange
                    ? "Strongly consistent with Android hiding the card's four-bit NAK after "
                            + "a wrong proof; still not cryptographic proof of rejection."
                    : "Consistent with Android hiding a four-bit NAK, but another generic NFC "
                            + "failure remains possible.";
        }
        if (terminal.failed()) {
            return "A proof-stage I/O failure occurred; the public Android API did not expose "
                    + "enough information to classify it.";
        }
        return "The final frame was exposed but did not form a valid mutual-authentication proof.";
    }

    private static void line(StringBuilder report, String label, String value) {
        report.append(label).append("  ").append(sanitize(value)).append('\n');
    }

    private static String proofStatus(int count) {
        if (count == 0) return "NOT SUBMITTED";
        if (count == 1) return "SUBMITTED ONCE";
        return "SAFETY VIOLATION: " + count + " SUBMISSIONS";
    }

    private static String proofReportStatus(int count) {
        if (count == 0) return "no";
        if (count == 1) return "yes, exactly once";
        return "SAFETY VIOLATION: " + count;
    }

    private static boolean hasRepeatedPhase(RecordingByteTransceiver trace) {
        int[] phaseCounts = new int[RecordingByteTransceiver.Phase.values().length];
        for (RecordingByteTransceiver.Exchange exchange : trace.exchanges()) {
            if (++phaseCounts[exchange.phase().ordinal()] > 1) return true;
        }
        return false;
    }

    private static String shortType(String type) {
        int separator = type.lastIndexOf('.');
        return separator < 0 ? type : type.substring(separator + 1);
    }

    private static String messageSuffix(String message) {
        String clean = sanitize(message);
        return clean.isEmpty() ? "" : ": " + clean;
    }

    private static String sanitize(String value) {
        if (value == null) return "";
        return value.replace('\n', ' ').replace('\r', ' ').trim();
    }

    private static String join(String[] values) {
        if (values == null || values.length == 0) return "";
        StringBuilder joined = new StringBuilder();
        for (String value : values) {
            if (joined.length() > 0) joined.append(", ");
            int separator = value == null ? -1 : value.lastIndexOf('.');
            joined.append(separator < 0 ? sanitize(value) : sanitize(value.substring(separator + 1)));
        }
        return joined.toString();
    }

    private static String formatDuration(long nanos) {
        double millis = Math.max(0, nanos) / 1_000_000.0;
        if (millis < 1.0) {
            return String.format(Locale.US, "%.3f ms", millis);
        }
        return String.format(Locale.US, "%.1f ms", millis);
    }
}
