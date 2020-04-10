package dpas.utils;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Set;
import java.util.stream.Collectors;

public class ByteUtils {
    public static byte[] toByteArray(Contract.SafePostRequest request) throws IOException {
        byte[] seq = NumberUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        byte[] pubKey = request.getPublicKey().toByteArray();
        byte[] message = request.getMessage().toByteArray();
        byte[] signature = request.getSignature().toByteArray();
        Set<byte[]> references = request.getReferencesList().stream().map(String::getBytes).collect(Collectors.toSet());
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            stream.writeBytes(pubKey);
            stream.writeBytes(message);
            stream.writeBytes(signature);
            stream.writeBytes(message);
            for (var ref : references) {
                stream.writeBytes(ref);
            }
            byte[] res = stream.toByteArray();
            return res;
        }
    }

    public static byte[] toByteArray(long sequence, String sessionNonce, PublicKey pubKey, byte[] message,
                                     byte[] signature, Set<String> references) throws IOException {
        byte[] seq = NumberUtils.longToBytes(sequence);
        byte[] nonce = sessionNonce.getBytes();
        byte[] key = pubKey.getEncoded();

        Set<byte[]> refs = references.stream().map(String::getBytes).collect(Collectors.toSet());
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            stream.writeBytes(key);
            stream.writeBytes(message);
            stream.writeBytes(signature);
            stream.writeBytes(message);
            for (var ref : refs) {
                stream.writeBytes(ref);
            }
            byte[] res = stream.toByteArray();
            return res;
        }
    }

    public static byte[] toByteArray(String sessionNonce, long sequence) throws IOException {
        byte[] seq = NumberUtils.longToBytes(sequence);
        byte[] nonce = sessionNonce.getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(String message, String sessionNonce, long sequence) throws IOException {
        byte[] messageBytes = message.getBytes();
        byte[] seq = NumberUtils.longToBytes(sequence);
        byte[] nonce = sessionNonce.getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(messageBytes);
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(String sessionNonce, PublicKey publicKey) throws IOException {
        byte[] nonce = sessionNonce.getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(publicKey.getEncoded());
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.SafeRegisterRequest request) throws IOException {
        byte[] seq = NumberUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        byte[] pubKey = request.getPublicKey().toByteArray();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            stream.writeBytes(pubKey);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.ClientHello request) throws IOException {
        byte[] nonce = request.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(request.getPublicKey().toByteArray());
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.ServerHello request) throws IOException {
        byte[] seq = NumberUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.SafeRegisterReply reply) throws IOException {
        byte[] seq = NumberUtils.longToBytes(reply.getSeq());
        byte[] nonce = reply.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.SafePostReply reply) throws IOException {
        byte[] seq = NumberUtils.longToBytes(reply.getSeq());
        byte[] nonce = reply.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.GoodByeRequest request) throws IOException {
        byte[] seq = NumberUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.ReadRequest request) {
        return request.getNonce().getBytes();
    }

    public static byte[] toByteArray(String sessionNonce, long sequence, PublicKey pubKey) throws IOException {
        byte[] seq = NumberUtils.longToBytes(sequence);
        byte[] nonce = sessionNonce.getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            stream.writeBytes(pubKey.getEncoded());
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(long sequence, PublicKey pubKey, byte[] message,
                                     byte[] signature, Set<String> references) throws IOException {
        byte[] seq = NumberUtils.longToBytes(sequence);
        byte[] key = pubKey.getEncoded();

        Set<byte[]> refs = references.stream().map(String::getBytes).collect(Collectors.toSet());
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(key);
            stream.writeBytes(message);
            stream.writeBytes(signature);
            stream.writeBytes(message);
            for (var ref : refs) {
                stream.writeBytes(ref);
            }
            byte[] res = stream.toByteArray();
            return res;
        }
    }

}
