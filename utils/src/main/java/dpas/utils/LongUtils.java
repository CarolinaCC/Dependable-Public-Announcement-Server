package dpas.utils;

import java.nio.ByteBuffer;

public class LongUtils {
    public synchronized static byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(Long.BYTES);
        buffer.putLong(0, x);
        return buffer.array();
    }
}