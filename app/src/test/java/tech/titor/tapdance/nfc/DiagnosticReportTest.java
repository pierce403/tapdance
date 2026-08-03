package tech.titor.tapdance.nfc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Queue;
import java.util.function.LongSupplier;

import org.junit.Test;

public final class DiagnosticReportTest {
    @Test
    public void genericProofFailureProducesStrongHiddenNakSignal() throws Exception {
        Queue<Object> responses = new ArrayDeque<>();
        responses.add(HexTest.decode("0004030104000F03"));
        responses.add(HexTest.decode("AF00112233445566778899AABBCCDDEEFF"));
        responses.add(new IOException("Transceive failed"));
        RecordingByteTransceiver trace = new RecordingByteTransceiver(
                command -> {
                    Object next = responses.remove();
                    if (next instanceof IOException) throw (IOException) next;
                    return (byte[]) next;
                },
                new ScriptedClock(0, 1, 2, 3, 4, 5, 6));

        trace.transceive(new byte[] {0x60});
        trace.transceive(new byte[] {0x1A, 0x00});
        try {
            trace.transceive(proofCommand());
        } catch (IOException ignored) {
            // The report must preserve the failed exchange.
        }

        AuthenticationResult result = AuthenticationResult.of(
                AuthenticationResult.Outcome.INCONCLUSIVE,
                "No reliable answer",
                HexTest.decode("04154EFA811690"),
                HexTest.decode("0004030104000F03"));
        DiagnosticReport.Metadata metadata = metadata();
        metadata.connectedAfterExchange = true;
        DiagnosticReport report = DiagnosticReport.create(result, trace, metadata);

        assertTrue(report.summary().contains("PHASE  AUTH_PROOF"));
        assertTrue(report.summary().contains("PROOF  SUBMITTED ONCE"));
        assertTrue(report.full().contains("Strongly consistent with Android hiding"));
        assertTrue(report.full().contains("IOException: Transceive failed"));
        assertTrue(report.full().contains("TX AF 00 00"));
        assertTrue(report.full().contains("DEVICE  Google Pixel 9 Pro"));
        assertTrue(report.full().contains("ATQA  44 00"));
        assertTrue(report.full().contains("TECH  NfcA, MifareUltralight"));
    }

    @Test
    public void localSessionCloseIsNotMisreportedAsHiddenNak() throws Exception {
        RecordingByteTransceiver trace = new RecordingByteTransceiver(
                command -> { throw new IOException("Transceive failed"); },
                new ScriptedClock(0, 10, 20));
        try {
            trace.transceive(proofCommand());
        } catch (IOException ignored) {
            // Expected.
        }

        AuthenticationResult result = AuthenticationResult.of(
                AuthenticationResult.Outcome.INCONCLUSIVE,
                "No reliable answer",
                new byte[] {1},
                HexTest.decode("0004030104000F03"));
        DiagnosticReport.Metadata metadata = metadata();
        metadata.connectedAfterExchange = true;
        metadata.cancelledDuringExchange = true;
        DiagnosticReport report = DiagnosticReport.create(result, trace, metadata);

        assertTrue(report.full().contains("app closed the NFC session"));
        assertFalse(report.full().contains("Strongly consistent"));
    }

    @Test
    public void duplicateProofSubmissionsAreFlaggedAsSafetyViolation() throws Exception {
        RecordingByteTransceiver trace = new RecordingByteTransceiver(
                command -> new byte[] {0x04},
                new ScriptedClock(0, 1, 2, 3, 4));
        trace.transceive(proofCommand());
        trace.transceive(proofCommand());

        AuthenticationResult result = AuthenticationResult.of(
                AuthenticationResult.Outcome.INCONCLUSIVE,
                "No reliable answer",
                new byte[] {1},
                HexTest.decode("0004030104000F03"));
        DiagnosticReport report = DiagnosticReport.create(result, trace, metadata());

        assertEquals(2, trace.proofSubmissionCount());
        assertTrue(report.summary().contains("SAFETY VIOLATION: 2 SUBMISSIONS"));
        assertTrue(report.full().contains("more than one candidate-key proof"));
        assertTrue(report.full().contains("repeated protocol phase"));
    }

    @Test
    public void tagLostFailureDoesNotSuggestWrongKey() throws Exception {
        RecordingByteTransceiver trace = new RecordingByteTransceiver(
                command -> { throw new FakeTagLostException("Tag was lost."); },
                new ScriptedClock(0, 10, 20));
        try {
            trace.transceive(proofCommand());
        } catch (IOException ignored) {
            // Expected.
        }

        AuthenticationResult result = AuthenticationResult.of(
                AuthenticationResult.Outcome.INCONCLUSIVE,
                "No reliable answer",
                new byte[] {1},
                HexTest.decode("0004030104000F03"));
        DiagnosticReport report = DiagnosticReport.create(result, trace, metadata());

        assertTrue(report.full().contains("Android reported RF tag loss"));
        assertFalse(report.full().contains("Strongly consistent"));
    }

    private static DiagnosticReport.Metadata metadata() {
        DiagnosticReport.Metadata metadata = new DiagnosticReport.Metadata();
        metadata.appVersion = "0.1.0-alpha.3 (3)";
        metadata.device = "Google Pixel 9 Pro";
        metadata.androidVersion = "17 / API 37";
        metadata.buildFingerprint = "google/test/device";
        metadata.technologies = new String[] {
            "android.nfc.tech.NfcA", "android.nfc.tech.MifareUltralight"
        };
        metadata.atqa = HexTest.decode("4400");
        metadata.sak = 0;
        metadata.maxTransceiveLength = 253;
        metadata.timeoutMillis = 1000;
        metadata.presenceCheckDelayMillis = 250;
        metadata.totalDurationNanos = 12_300_000;
        return metadata;
    }

    private static byte[] proofCommand() {
        byte[] proof = new byte[33];
        proof[0] = (byte) 0xAF;
        return proof;
    }

    private static final class FakeTagLostException extends IOException {
        private static final long serialVersionUID = 1L;

        private FakeTagLostException(String message) {
            super(message);
        }
    }

    private static final class ScriptedClock implements LongSupplier {
        private final Queue<Long> readings = new ArrayDeque<>();

        private ScriptedClock(long... values) {
            for (long value : values) readings.add(value);
        }

        @Override
        public long getAsLong() {
            return readings.remove();
        }
    }
}
