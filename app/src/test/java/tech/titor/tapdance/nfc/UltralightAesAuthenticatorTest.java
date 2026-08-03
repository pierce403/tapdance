package tech.titor.tapdance.nfc;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.Test;

public final class UltralightAesAuthenticatorTest {
    private static final byte[] VERSION = HexTest.decode("0004030104000F03");
    private static final byte[] RND_B = HexTest.decode("1AE4174CA173EBBC59165CEBE2F20821");
    private static final byte[] ENC_RND_B = HexTest.decode("D5A847B84862FF3874A7F07B8DDF351B");
    private static final byte[] RND_A = HexTest.decode("F29B0123F5C00DF612487BBF42468C7E");
    private static final byte[] ENC_AB = HexTest.decode(
            "CDF22C5F7A92F0AF0155612B9B236AC7A424BC5238D41AD041B8165B7D99E524");
    private static final byte[] ENC_ROTATED_RND_A =
            HexTest.decode("2C743D6B1E128F8076BD197B76012CE8");

    @Test
    public void officialNxpVectorBuildsExactSecondFrame() throws Exception {
        assertArrayEquals(RND_B, UltralightAesAuthenticator.aesCbc(
                false, new byte[16], ENC_RND_B));

        byte[] expected = concat(new byte[] {(byte) 0xAF}, ENC_AB);
        assertArrayEquals(expected, UltralightAesAuthenticator.buildSecondCommand(
                new byte[16], RND_A, RND_B));
    }

    @Test
    public void secondIndependentNxpVectorBuildsExactSecondFrame() throws Exception {
        byte[] rndB = HexTest.decode("0D2BBA17011098E9864C8AA5192AF796");
        byte[] encryptedRndB = HexTest.decode("374142DAFB0AB97183D846EB7ED379E0");
        byte[] rndA = HexTest.decode("42BDF7E08E110F14B6D3323D14F1C2B9");
        byte[] encryptedAb = HexTest.decode(
                "794693B2A31E7F10964A2BD834590AC485F84E9F8B13197AB32433346F60B821");

        assertArrayEquals(rndB, UltralightAesAuthenticator.aesCbc(
                false, new byte[16], encryptedRndB));
        assertArrayEquals(
                concat(new byte[] {(byte) 0xAF}, encryptedAb),
                UltralightAesAuthenticator.buildSecondCommand(new byte[16], rndA, rndB));
    }

    @Test
    public void completeOfficialExchangeIsAcceptedAndUsesOnlyThreeCommands() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                concat(new byte[] {(byte) 0xAF}, ENC_RND_B),
                concat(new byte[] {0x00}, ENC_ROTATED_RND_A));

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, HexTest.decode("0439BBAA816990"), bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.ACCEPTED, result.outcome());
        assertEquals(3, radio.commands.size());
        assertArrayEquals(new byte[] {0x60}, radio.commands.get(0));
        assertArrayEquals(new byte[] {0x1A, 0x00}, radio.commands.get(1));
        assertArrayEquals(concat(new byte[] {(byte) 0xAF}, ENC_AB), radio.commands.get(2));
    }

    @Test
    public void explicitNakIsRejectedWithoutRetry() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                concat(new byte[] {(byte) 0xAF}, ENC_RND_B),
                new byte[] {0x04});

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, new byte[] {1}, bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.REJECTED, result.outcome());
        assertEquals(3, radio.commands.size());
    }

    @Test
    public void hiddenNakIOExceptionAfterSubmissionIsInconclusiveAndNeverRetried() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                concat(new byte[] {(byte) 0xAF}, ENC_RND_B),
                new IOException("NAK hidden by controller"));

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, new byte[] {1}, bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.INCONCLUSIVE, result.outcome());
        assertEquals(3, radio.commands.size());
    }

    @Test
    public void wrongVersionNeverStartsAuthentication() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                HexTest.decode("0004030102000F03"));

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, new byte[] {1}, bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.UNSUPPORTED, result.outcome());
        assertEquals(1, radio.commands.size());
    }

    @Test
    public void malformedFirstFrameNeverSubmitsCandidateProof() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                new byte[] {(byte) 0xAF});

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, new byte[] {1}, bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.INCONCLUSIVE, result.outcome());
        assertEquals(2, radio.commands.size());
    }

    @Test
    public void malformedFinalFrameDoesNotRetry() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                concat(new byte[] {(byte) 0xAF}, ENC_RND_B),
                new byte[] {0x00, 0x01});

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, new byte[] {1}, bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.INCONCLUSIVE, result.outcome());
        assertEquals(3, radio.commands.size());
    }

    @Test
    public void cancellationAfterVersionPreventsAuthenticationCommand() {
        ScriptedTransceiver radio = new ScriptedTransceiver(VERSION);

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio,
                new byte[] {1},
                bytes -> copy(RND_A, bytes),
                () -> radio.commands.size() >= 1);

        assertEquals(AuthenticationResult.Outcome.INCONCLUSIVE, result.outcome());
        assertEquals(1, radio.commands.size());
    }

    @Test
    public void cancellationAfterChallengePreventsCandidateProof() {
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                concat(new byte[] {(byte) 0xAF}, ENC_RND_B));

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio,
                new byte[] {1},
                bytes -> copy(RND_A, bytes),
                () -> radio.commands.size() >= 2);

        assertEquals(AuthenticationResult.Outcome.INCONCLUSIVE, result.outcome());
        assertEquals(2, radio.commands.size());
    }

    @Test
    public void mismatchedFinalProofIsInconclusive() {
        byte[] corrupt = Arrays.copyOf(ENC_ROTATED_RND_A, ENC_ROTATED_RND_A.length);
        corrupt[7] ^= 1;
        ScriptedTransceiver radio = new ScriptedTransceiver(
                VERSION,
                concat(new byte[] {(byte) 0xAF}, ENC_RND_B),
                concat(new byte[] {0x00}, corrupt));

        AuthenticationResult result = UltralightAesAuthenticator.testFactoryDataKey(
                radio, new byte[] {1}, bytes -> copy(RND_A, bytes));

        assertEquals(AuthenticationResult.Outcome.INCONCLUSIVE, result.outcome());
        assertEquals(3, radio.commands.size());
    }

    private static void copy(byte[] source, byte[] target) {
        System.arraycopy(source, 0, target, 0, target.length);
    }

    private static byte[] concat(byte[] first, byte[] second) {
        byte[] result = Arrays.copyOf(first, first.length + second.length);
        System.arraycopy(second, 0, result, first.length, second.length);
        return result;
    }

    private static final class ScriptedTransceiver implements ByteTransceiver {
        private final Object[] responses;
        private int cursor;
        private final List<byte[]> commands = new ArrayList<>();

        private ScriptedTransceiver(Object... responses) {
            this.responses = responses;
        }

        @Override
        public byte[] transceive(byte[] command) throws IOException {
            commands.add(Arrays.copyOf(command, command.length));
            Object response = responses[cursor++];
            if (response instanceof IOException) throw (IOException) response;
            return Arrays.copyOf((byte[]) response, ((byte[]) response).length);
        }
    }
}
