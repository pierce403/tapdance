package tech.titor.tapdance.nfc;

import java.io.IOException;

@FunctionalInterface
public interface ByteTransceiver {
    byte[] transceive(byte[] command) throws IOException;
}

