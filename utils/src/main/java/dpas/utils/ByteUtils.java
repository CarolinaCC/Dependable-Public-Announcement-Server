package dpas.utils;

import dpas.grpc.contract.Contract;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.Set;
import java.util.stream.Collectors;

public class ByteUtils {

    public static byte[] toByteArray(Contract.MacReply reply) throws IOException {
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            byte[] res = stream.toByteArray();
            return res;
        }
    }

    public static byte[] toByteArray(Contract.PostRequest request) throws IOException {
        byte[] seq = NumberUtils.longToBytes(request.getSeq());
        byte[] pubKey = request.getPublicKey().toByteArray();
        byte[] message = request.getMessage().getBytes();
        byte[] signature = request.getSignature().toByteArray();
        Set<byte[]> references = request.getReferencesList().stream().map(String::getBytes).collect(Collectors.toSet());
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(pubKey);
            stream.writeBytes(message);
            stream.writeBytes(signature);
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
            for (var ref : refs) {
                stream.writeBytes(ref);
            }
            byte[] res = stream.toByteArray();
            return res;
        }
    }

    public static byte[] toByteArray(PublicKey pubKey) throws IOException {
        byte[] key = pubKey.getEncoded();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(key);
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


    public static byte[] toByteArray(Contract.RegisterRequest request) throws IOException {
        byte[] pubKey = request.getPublicKey().toByteArray();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(pubKey);
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

    public static byte[] toByteArray(long seq, PublicKey pubKey, String message, byte[] signature, Set<String> references) throws IOException {
        byte[] seqBytes = NumberUtils.longToBytes(seq);
        byte[] key = pubKey.getEncoded();
        byte[] messageBytes = message.getBytes();
        Set<byte[]> refs = references.stream().map(String::getBytes).collect(Collectors.toSet());
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seqBytes);
            stream.writeBytes(key);
            stream.writeBytes(messageBytes);
            stream.writeBytes(signature);
            for (var ref : refs) {
                stream.writeBytes(ref);
            }
            byte[] res = stream.toByteArray();
            return res;
        }
    }
}
