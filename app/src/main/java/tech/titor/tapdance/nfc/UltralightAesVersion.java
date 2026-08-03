package tech.titor.tapdance.nfc;

import java.util.Arrays;

/** Exact recognition of NXP MIFARE Ultralight AES GET_VERSION data. */
public final class UltralightAesVersion {
    public static final byte GET_VERSION = 0x60;
    public static final int RESPONSE_LENGTH = 8;

    private final byte[] raw;

    private UltralightAesVersion(byte[] raw) {
        this.raw = Arrays.copyOf(raw, raw.length);
    }

    public static UltralightAesVersion parse(byte[] response) throws ProtocolException {
        if (response == null || response.length != RESPONSE_LENGTH) {
            throw new ProtocolException("GET_VERSION returned "
                    + (response == null ? 0 : response.length) + " bytes; expected 8");
        }

        boolean expectedFamily = response[0] == 0x00
                && response[1] == 0x04
                && response[2] == 0x03
                && (response[3] == 0x01 || response[3] == 0x02)
                && response[4] == 0x04
                && response[5] == 0x00
                && response[6] == 0x0F
                && response[7] == 0x03;

        if (!expectedFamily) {
            throw new ProtocolException("Tag is not an NXP MIFARE Ultralight AES MF0AESx20");
        }
        return new UltralightAesVersion(response);
    }

    public byte[] raw() {
        return Arrays.copyOf(raw, raw.length);
    }

    public String capacitance() {
        return raw[3] == 0x01 ? "17 pF" : "50 pF";
    }

    public static final class ProtocolException extends Exception {
        private static final long serialVersionUID = 1L;

        public ProtocolException(String message) {
            super(message);
        }
    }
}
