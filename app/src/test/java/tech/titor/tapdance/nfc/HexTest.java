package tech.titor.tapdance.nfc;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public final class HexTest {
    @Test
    public void formatsUnsignedBytes() {
        assertEquals("00AF", Hex.encode(new byte[] {0x00, (byte) 0xAF}));
        assertEquals("00 AF", Hex.encodeSpaced(new byte[] {0x00, (byte) 0xAF}));
    }

    static byte[] decode(String hex) {
        if ((hex.length() & 1) != 0) throw new IllegalArgumentException("Odd hex length");
        byte[] output = new byte[hex.length() / 2];
        for (int index = 0; index < output.length; index++) {
            output[index] = (byte) Integer.parseInt(
                    hex.substring(index * 2, index * 2 + 2), 16);
        }
        return output;
    }
}
