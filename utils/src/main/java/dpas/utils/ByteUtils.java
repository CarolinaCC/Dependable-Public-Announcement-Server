package dpas.utils;

import dpas.grpc.contract.Contract;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class ByteUtils {

    public static byte[] toByteArray(Contract.PostRequest request) {
        return request.toByteArray();
    }

    public static byte[] toByteArray(Contract.RegisterRequest request) {
        return request.toByteArray();
    }

    public static byte[] toByteArray(Contract.ReadRequest request, List<Contract.Announcement> reply) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(request.toByteArray());
            reply.stream().map(ByteUtils::toByteArray).forEach(stream::writeBytes);
            return stream.toByteArray();
        }
    }

    private static byte[] toByteArray(Contract.Announcement announcement) {
        return announcement.toByteArray();
    }

    public static byte[] toByteArray(String nonce, long seq, PublicKey pubKey) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(NumberUtils.longToBytes(seq));
            stream.writeBytes(nonce.getBytes());
            stream.writeBytes(pubKey.getEncoded());
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(long seq, PublicKey pubKey, String message, byte[] signature, Set<String> references) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(NumberUtils.longToBytes(seq));
            stream.writeBytes(pubKey.getEncoded());
            stream.writeBytes(message.getBytes());
            stream.writeBytes(signature);
            references.stream().map(String::getBytes).forEach(stream::writeBytes);
            return stream.toByteArray();
        }
    }
}
