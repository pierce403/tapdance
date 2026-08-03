package tech.titor.tapdance.nfc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.junit.Test;

public final class UltralightAesVersionTest {
    @Test
    public void acceptsBothDocumentedInputCapacitances() throws Exception {
        assertEquals("17 pF", UltralightAesVersion.parse(
                HexTest.decode("0004030104000F03")).capacitance());
        assertEquals("50 pF", UltralightAesVersion.parse(
                HexTest.decode("0004030204000F03")).capacitance());
    }

    @Test
    public void rejectsDifferentProductAndWrongLength() {
        assertRejected("0004030102000F03");
        assertRejected("0004030104000F");
    }

    private static void assertRejected(String hex) {
        try {
            UltralightAesVersion.parse(HexTest.decode(hex));
            fail("Expected ProtocolException");
        } catch (UltralightAesVersion.ProtocolException expected) {
            // Expected.
        }
    }
}
