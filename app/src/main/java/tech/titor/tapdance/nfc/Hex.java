package tech.titor.tapdance.nfc;

import java.util.Locale;

public final class Hex {
    private Hex() {}

    public static String encode(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder output = new StringBuilder(bytes.length * 2);
        for (byte value : bytes) {
            output.append(String.format(Locale.US, "%02X", value & 0xFF));
        }
        return output.toString();
    }

    public static String encodeSpaced(byte[] bytes) {
        if (bytes == null) return "";
        StringBuilder output = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) output.append(' ');
            output.append(String.format(Locale.US, "%02X", bytes[i] & 0xFF));
        }
        return output.toString();
    }
}

