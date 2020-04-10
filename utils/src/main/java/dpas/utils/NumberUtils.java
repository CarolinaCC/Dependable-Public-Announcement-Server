package dpas.utils;

import java.nio.ByteBuffer;

public class NumberUtils {
    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(0, x);
        return buffer.array();
    }
}