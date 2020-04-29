package dpas.utils;

import java.nio.ByteBuffer;

public final class NumberUtils {

    private NumberUtils() {
    }

    public static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(0, x);
        return buffer.array();
    }

    public static byte[] intToBytes(int x) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.putInt(0, x);
        return buffer.array();
    }
}