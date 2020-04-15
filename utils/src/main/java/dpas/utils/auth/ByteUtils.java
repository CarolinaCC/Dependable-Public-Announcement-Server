package dpas.utils.auth;

import dpas.grpc.contract.Contract;
import dpas.utils.NumberUtils;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Set;

public class ByteUtils {

    public static byte[] toByteArray(Contract.Announcement request) {
        byte[] seq = NumberUtils.longToBytes(request.getSeq());
        byte[] pubKey = request.getPublicKey().toByteArray();
        byte[] message = request.getMessage().getBytes();
        byte[] signature = request.getSignature().toByteArray();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(pubKey);
            stream.writeBytes(message);
            stream.writeBytes(signature);
            request.getReferencesList().stream()
                    .map(String::getBytes)
                    .forEach(stream::writeBytes);

            return stream.toByteArray();
        } catch (IOException e) {
            return new byte[0];
        }
    }

    public static byte[] toByteArray(Contract.RegisterRequest request) {
        return request.getPublicKey().toByteArray();
    }

    public static byte[] toByteArray(Contract.ReadRequest request, int announcementCount) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(request.toByteArray());
            stream.writeBytes(NumberUtils.intToBytes(announcementCount));
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(String nonce, long seq, PublicKey pubKey) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(NumberUtils.longToBytes(seq));
            stream.writeBytes(nonce.getBytes());
            stream.writeBytes(pubKey.getEncoded());
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(String nonce, long seq) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(NumberUtils.longToBytes(seq));
            stream.writeBytes(nonce.getBytes());
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
