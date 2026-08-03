package tech.titor.tapdance.nfc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.ArrayDeque;
import java.util.Arrays;
import java.util.Queue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.LongSupplier;

import org.junit.Test;

public final class RecordingByteTransceiverTest {
    @Test
    public void recordsThreeExistingFramesWithoutRetrying() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        Queue<byte[]> responses = new ArrayDeque<>();
        responses.add(HexTest.decode("0004030104000F03"));
        responses.add(HexTest.decode("AF00112233445566778899AABBCCDDEEFF"));
        responses.add(HexTest.decode("0000112233445566778899AABBCCDDEEFF"));
        RecordingByteTransceiver recorder = new RecordingByteTransceiver(
                command -> {
                    calls.incrementAndGet();
                    return responses.remove();
                },
                new ScriptedClock(0, 10, 20, 30, 40, 50, 60));

        recorder.transceive(new byte[] {0x60});
        recorder.transceive(new byte[] {0x1A, 0x00});
        recorder.transceive(concat(
                new byte[] {(byte) 0xAF},
                new byte[32]));

        assertEquals(3, calls.get());
        assertEquals(3, recorder.exchanges().size());
        assertEquals(
                RecordingByteTransceiver.Phase.GET_VERSION,
                recorder.exchanges().get(0).phase());
        assertEquals(
                RecordingByteTransceiver.Phase.AUTH_CHALLENGE,
                recorder.exchanges().get(1).phase());
        assertEquals(
                RecordingByteTransceiver.Phase.AUTH_PROOF,
                recorder.exchanges().get(2).phase());
        assertTrue(recorder.proofSubmitted());
        assertEquals(1, recorder.proofSubmissionCount());
        assertFalse(recorder.exchanges().get(2).failed());
        assertEquals(10, recorder.exchanges().get(2).durationNanos());
    }

    @Test
    public void recordsProofIOExceptionAndRethrowsUnchanged() throws Exception {
        IOException expected = new IOException("Transceive failed");
        AtomicInteger calls = new AtomicInteger();
        RecordingByteTransceiver recorder = new RecordingByteTransceiver(
                command -> {
                    calls.incrementAndGet();
                    throw expected;
                },
                new ScriptedClock(100, 120, 155));

        IOException actual = null;
        try {
            recorder.transceive(concat(new byte[] {(byte) 0xAF}, new byte[32]));
        } catch (IOException error) {
            actual = error;
        }

        assertEquals(expected, actual);
        assertEquals(1, calls.get());
        assertEquals(1, recorder.exchanges().size());
        RecordingByteTransceiver.Exchange exchange = recorder.exchanges().get(0);
        assertEquals(RecordingByteTransceiver.Phase.AUTH_PROOF, exchange.phase());
        assertTrue(exchange.failed());
        assertEquals("java.io.IOException", exchange.errorType());
        assertEquals("Transceive failed", exchange.errorMessage());
        assertEquals(35, exchange.durationNanos());
        assertTrue(recorder.proofSubmitted());
    }

    @Test
    public void strictClassifierRejectsNearMissCommands() throws Exception {
        RecordingByteTransceiver empty = new RecordingByteTransceiver(
                command -> new byte[0],
                new ScriptedClock(0));
        assertEquals(RecordingByteTransceiver.Phase.OTHER, empty.terminalPhase());

        RecordingByteTransceiver recorder = new RecordingByteTransceiver(
                command -> new byte[0],
                new ScriptedClock(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10));
        recorder.transceive(new byte[] {0x60, 0x00});
        recorder.transceive(new byte[] {0x1A, 0x01});
        recorder.transceive(concat(new byte[] {(byte) 0xAF}, new byte[31]));
        recorder.transceive(concat(new byte[] {(byte) 0xAF}, new byte[33]));
        recorder.transceive(new byte[] {0x30, 0x00});

        assertEquals(5, recorder.exchanges().size());
        for (RecordingByteTransceiver.Exchange exchange : recorder.exchanges()) {
            assertEquals(RecordingByteTransceiver.Phase.OTHER, exchange.phase());
        }
        assertEquals(RecordingByteTransceiver.Phase.OTHER, recorder.terminalPhase());
        assertEquals(0, recorder.proofSubmissionCount());
    }

    @Test
    public void copiesCommandsAndResponsesDefensively() throws Exception {
        byte[] command = new byte[] {0x60};
        byte[] response = HexTest.decode("0004030104000F03");
        RecordingByteTransceiver recorder = new RecordingByteTransceiver(
                transportCommand -> {
                    transportCommand[0] = 0x00;
                    return response;
                },
                new ScriptedClock(0, 1, 2));

        byte[] returned = recorder.transceive(command);
        command[0] = 0x00;
        response[0] = 0x7F;
        returned[1] = 0x7F;

        assertArrayEquals(new byte[] {0x60}, recorder.exchanges().get(0).command());
        assertArrayEquals(
                HexTest.decode("0004030104000F03"),
                recorder.exchanges().get(0).response());
        byte[] leaked = recorder.exchanges().get(0).response();
        leaked[0] = 0x7F;
        assertArrayEquals(
                HexTest.decode("0004030104000F03"),
                recorder.exchanges().get(0).response());
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
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
