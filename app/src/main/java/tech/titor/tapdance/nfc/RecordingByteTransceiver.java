package tech.titor.tapdance.nfc;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.function.LongSupplier;

/** Records the existing NFC exchange without adding, suppressing, or retrying any frame. */
public final class RecordingByteTransceiver implements ByteTransceiver {
    public enum Phase {
        GET_VERSION,
        AUTH_CHALLENGE,
        AUTH_PROOF,
        OTHER
    }

    public static final class Exchange {
        private final Phase phase;
        private final byte[] command;
        private final byte[] response;
        private final long offsetNanos;
        private final long durationNanos;
        private final String errorType;
        private final String errorMessage;

        private Exchange(
                Phase phase,
                byte[] command,
                byte[] response,
                long offsetNanos,
                long durationNanos,
                IOException error) {
            this.phase = phase;
            this.command = Arrays.copyOf(command, command.length);
            this.response = response == null ? new byte[0] : Arrays.copyOf(response, response.length);
            this.offsetNanos = Math.max(0, offsetNanos);
            this.durationNanos = Math.max(0, durationNanos);
            this.errorType = error == null ? "" : error.getClass().getName();
            this.errorMessage = error == null || error.getMessage() == null
                    ? ""
                    : error.getMessage();
        }

        public Phase phase() {
            return phase;
        }

        public byte[] command() {
            return Arrays.copyOf(command, command.length);
        }

        public byte[] response() {
            return Arrays.copyOf(response, response.length);
        }

        public long offsetNanos() {
            return offsetNanos;
        }

        public long durationNanos() {
            return durationNanos;
        }

        public String errorType() {
            return errorType;
        }

        public String errorMessage() {
            return errorMessage;
        }

        public boolean failed() {
            return !errorType.isEmpty();
        }
    }

    private final ByteTransceiver delegate;
    private final LongSupplier nanoClock;
    private final long traceStartNanos;
    private final List<Exchange> exchanges = new ArrayList<>();

    public RecordingByteTransceiver(ByteTransceiver delegate) {
        this(delegate, System::nanoTime);
    }

    RecordingByteTransceiver(ByteTransceiver delegate, LongSupplier nanoClock) {
        this.delegate = delegate;
        this.nanoClock = nanoClock;
        this.traceStartNanos = nanoClock.getAsLong();
    }

    @Override
    public byte[] transceive(byte[] command) throws IOException {
        byte[] recordedCommand = Arrays.copyOf(command, command.length);
        byte[] transportCommand = Arrays.copyOf(command, command.length);
        Phase phase = classify(recordedCommand);
        long startedNanos = nanoClock.getAsLong();
        try {
            byte[] response = delegate.transceive(transportCommand);
            long finishedNanos = nanoClock.getAsLong();
            exchanges.add(new Exchange(
                    phase,
                    recordedCommand,
                    response,
                    startedNanos - traceStartNanos,
                    finishedNanos - startedNanos,
                    null));
            return response == null ? null : Arrays.copyOf(response, response.length);
        } catch (IOException error) {
            long finishedNanos = nanoClock.getAsLong();
            exchanges.add(new Exchange(
                    phase,
                    recordedCommand,
                    null,
                    startedNanos - traceStartNanos,
                    finishedNanos - startedNanos,
                    error));
            throw error;
        }
    }

    public List<Exchange> exchanges() {
        return Collections.unmodifiableList(new ArrayList<>(exchanges));
    }

    public boolean proofSubmitted() {
        return proofSubmissionCount() > 0;
    }

    public int proofSubmissionCount() {
        int count = 0;
        for (Exchange exchange : exchanges) {
            if (exchange.phase() == Phase.AUTH_PROOF) count++;
        }
        return count;
    }

    public Phase terminalPhase() {
        return exchanges.isEmpty()
                ? Phase.OTHER
                : exchanges.get(exchanges.size() - 1).phase();
    }

    private static Phase classify(byte[] command) {
        if (command.length == 1 && command[0] == 0x60) {
            return Phase.GET_VERSION;
        }
        if (command.length == 2 && command[0] == 0x1A && command[1] == 0x00) {
            return Phase.AUTH_CHALLENGE;
        }
        if (command.length == 33 && command[0] == (byte) 0xAF) {
            return Phase.AUTH_PROOF;
        }
        return Phase.OTHER;
    }
}
