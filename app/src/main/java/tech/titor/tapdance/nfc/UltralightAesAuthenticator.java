package tech.titor.tapdance.nfc;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Performs one MIFARE Ultralight AES mutual-authentication attempt with the factory
 * DataProtKey. The command set is deliberately restricted to GET_VERSION and AUTHENTICATE.
 */
public final class UltralightAesAuthenticator {
    private static final byte[] FACTORY_DATA_KEY = new byte[16];
    private static final byte ADDITIONAL_FRAME = (byte) 0xAF;
    private static final byte AUTHENTICATE = 0x1A;
    private static final byte DATA_PROT_KEY_NUMBER = 0x00;

    private UltralightAesAuthenticator() {}

    @FunctionalInterface
    public interface RandomSource {
        void nextBytes(byte[] destination);
    }

    public static AuthenticationResult testFactoryDataKey(
            ByteTransceiver transceiver, byte[] uid, RandomSource random) {
        return testFactoryDataKey(transceiver, uid, random, () -> false);
    }

    @FunctionalInterface
    public interface CancellationSignal {
        boolean isCancelled();
    }

    public static AuthenticationResult testFactoryDataKey(
            ByteTransceiver transceiver,
            byte[] uid,
            RandomSource random,
            CancellationSignal cancellation) {
        if (cancellation.isCancelled()) {
            return cancelled(uid, null);
        }
        byte[] versionResponse;
        try {
            versionResponse = transceiver.transceive(
                    new byte[] {UltralightAesVersion.GET_VERSION});
        } catch (IOException error) {
            return inconclusive(
                    "The tag stopped responding before TapDance submitted an authentication "
                            + "attempt. No key guess was sent.",
                    uid,
                    null);
        }

        final UltralightAesVersion version;
        try {
            version = UltralightAesVersion.parse(versionResponse);
        } catch (UltralightAesVersion.ProtocolException error) {
            return AuthenticationResult.of(
                    AuthenticationResult.Outcome.UNSUPPORTED,
                    error.getMessage() + ". No authentication attempt was made.",
                    uid,
                    versionResponse);
        }

        if (cancellation.isCancelled()) {
            return cancelled(uid, version.raw());
        }

        final byte[] encryptedRndB;
        try {
            byte[] partOne = transceiver.transceive(
                    new byte[] {AUTHENTICATE, DATA_PROT_KEY_NUMBER});
            if (isNak(partOne)) {
                return inconclusive(
                        "The tag declined the authentication command before a key guess was "
                                + "submitted.",
                        uid,
                        version.raw());
            }
            if (partOne == null || partOne.length != 17 || partOne[0] != ADDITIONAL_FRAME) {
                return inconclusive(
                        "The tag returned an unexpected first authentication frame. No key "
                                + "guess was submitted.",
                        uid,
                        version.raw());
            }
            encryptedRndB = Arrays.copyOfRange(partOne, 1, partOne.length);
        } catch (IOException error) {
            return inconclusive(
                    "Communication ended before TapDance submitted the key guess.",
                    uid,
                    version.raw());
        }


        if (cancellation.isCancelled()) {
            return cancelled(uid, version.raw());
        }

        final byte[] secondCommand;
        final byte[] expectedRotatedRndA;
        try {
            byte[] rndB = aesCbc(false, FACTORY_DATA_KEY, encryptedRndB);
            byte[] rndA = new byte[16];
            random.nextBytes(rndA);
            secondCommand = buildSecondCommand(FACTORY_DATA_KEY, rndA, rndB);
            expectedRotatedRndA = rotateLeftOneByte(rndA);
        } catch (GeneralSecurityException error) {
            return inconclusive(
                    "Android's AES provider could not prepare the authentication proof.",
                    uid,
                    version.raw());
        }

        if (cancellation.isCancelled()) {
            return cancelled(uid, version.raw());
        }

        // Calling transceive here commits the one candidate-key attempt. Never retry it.
        final byte[] finalFrame;
        try {
            finalFrame = transceiver.transceive(secondCommand);
        } catch (IOException error) {
            return inconclusive(
                    "The card did not return a valid mutual-authentication proof. Android may "
                            + "hide the card's rejection response; do not retry blindly. This "
                            + "one key guess was submitted.",
                    uid,
                    version.raw());
        }

        if (isNak(finalFrame)) {
            return AuthenticationResult.of(
                    AuthenticationResult.Outcome.REJECTED,
                    "The tag explicitly rejected the all-zero factory DataProtKey. This one "
                            + "key guess was submitted.",
                    uid,
                    version.raw());
        }
        if (finalFrame == null || finalFrame.length != 17 || finalFrame[0] != 0x00) {
            return inconclusive(
                    "The tag returned an unexpected final authentication frame after the one "
                            + "key guess was submitted.",
                    uid,
                    version.raw());
        }

        try {
            byte[] returnedRotatedRndA = aesCbc(
                    false, FACTORY_DATA_KEY, Arrays.copyOfRange(finalFrame, 1, finalFrame.length));
            if (MessageDigest.isEqual(expectedRotatedRndA, returnedRotatedRndA)) {
                return AuthenticationResult.of(
                        AuthenticationResult.Outcome.ACCEPTED,
                        "The tag completed mutual authentication with the factory DataProtKey.",
                        uid,
                        version.raw());
            }
            return inconclusive(
                    "The tag returned a malformed mutual-authentication proof. The result is not "
                            + "a reliable rejection.",
                    uid,
                    version.raw());
        } catch (GeneralSecurityException error) {
            return inconclusive(
                    "Android's AES provider could not verify the authentication proof.",
                    uid,
                    version.raw());
        }
    }

    static byte[] buildSecondCommand(byte[] key, byte[] rndA, byte[] rndB)
            throws GeneralSecurityException {
        if (rndA.length != 16 || rndB.length != 16) {
            throw new IllegalArgumentException("RndA and RndB must each be 16 bytes");
        }
        byte[] plaintext = new byte[32];
        System.arraycopy(rndA, 0, plaintext, 0, 16);
        System.arraycopy(rotateLeftOneByte(rndB), 0, plaintext, 16, 16);
        byte[] encrypted = aesCbc(true, key, plaintext);
        byte[] command = new byte[33];
        command[0] = ADDITIONAL_FRAME;
        System.arraycopy(encrypted, 0, command, 1, encrypted.length);
        return command;
    }

    static byte[] rotateLeftOneByte(byte[] input) {
        if (input.length == 0) return new byte[0];
        byte[] rotated = new byte[input.length];
        System.arraycopy(input, 1, rotated, 0, input.length - 1);
        rotated[input.length - 1] = input[0];
        return rotated;
    }

    static byte[] aesCbc(boolean encrypt, byte[] key, byte[] input)
            throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
        cipher.init(
                encrypt ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE,
                new SecretKeySpec(key, "AES"),
                new IvParameterSpec(new byte[16]));
        return cipher.doFinal(input);
    }

    private static boolean isNak(byte[] frame) {
        if (frame == null || frame.length != 1) return false;
        int value = frame[0] & 0xFF;
        return value == 0x00
                || value == 0x01
                || value == 0x04
                || value == 0x05
                || value == 0x06
                || value == 0x07;
    }

    private static AuthenticationResult inconclusive(
            String detail, byte[] uid, byte[] version) {
        return AuthenticationResult.of(
                AuthenticationResult.Outcome.INCONCLUSIVE, detail, uid, version);
    }

    private static AuthenticationResult cancelled(byte[] uid, byte[] version) {
        return inconclusive(
                "The test was cancelled before the candidate-key proof was submitted. No key "
                        + "guess was sent.",
                uid,
                version);
    }
}
