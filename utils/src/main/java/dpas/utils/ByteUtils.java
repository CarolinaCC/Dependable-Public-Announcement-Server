package dpas.utils;

import dpas.grpc.contract.Contract;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.PublicKey;
import java.util.List;
import java.util.stream.Collectors;

public class ByteUtils {
    public static byte[] toByteArray(Contract.SafePostRequest request) throws IOException {
        byte[] seq = LongUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        byte[] pubKey = request.getPublicKey().toByteArray();
        byte[] message = request.getMessage().toByteArray();
        byte[] signature = request.getSignature().toByteArray();
        List<byte[]> references = request.getReferencesList().stream().map(String::getBytes).collect(Collectors.toList());
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

    public static byte[] toByteArray(String sessionNonce, long sequence) throws IOException {
        byte[] seq = LongUtils.longToBytes(sequence);
        byte[] nonce = sessionNonce.getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
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
        byte[] seq = LongUtils.longToBytes(request.getSeq());
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
        byte[] seq = LongUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.SafeRegisterReply reply) throws IOException {
        byte[] seq = LongUtils.longToBytes(reply.getSeq());
        byte[] nonce = reply.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.SafePostReply reply) throws IOException {
        byte[] seq = LongUtils.longToBytes(reply.getSeq());
        byte[] nonce = reply.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.GoodByeRequest request) throws IOException {
        byte[] seq = LongUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }
}
