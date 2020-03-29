package dpas.utils.bytes;

import dpas.grpc.contract.Contract;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.List;
import java.util.stream.Collectors;

public class ContractUtils {
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
            for(var ref: references) {
                stream.writeBytes(ref);
            }
            return stream.toByteArray();
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


    public static byte[] toByteArray(Contract.SafePostReply reply) throws IOException {
        byte[] seq = LongUtils.longToBytes(reply.getSeq());
        byte[] nonce = reply.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
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
            return stream.toByteArray();
        }
    }

    public static byte[] toByteArray(Contract.SafeRegisterReply request) throws IOException {
        byte[] seq = LongUtils.longToBytes(request.getSeq());
        byte[] nonce = request.getSessionNonce().getBytes();
        try (ByteArrayOutputStream stream = new ByteArrayOutputStream()) {
            stream.writeBytes(seq);
            stream.writeBytes(nonce);
            return stream.toByteArray();
        }
    }



    public static byte[] generateMac(Contract.SafePostRequest request, PrivateKey privKey) throws IOException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] content = toByteArray(request);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(encodedhash);
    }

    public static byte[] generateMac(String sessionNonce, long seq, PrivateKey privKey) throws IOException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] content = toByteArray(sessionNonce, seq);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(encodedhash);
    }


    public static byte[] generateMac(Contract.SafePostReply reply, PrivateKey privKey) throws IOException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] content = toByteArray(reply);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(encodedhash);
    }

    public static byte[] generateMac(Contract.SafeRegisterRequest request, PrivateKey privKey) throws IOException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] content = toByteArray(request);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(encodedhash);
    }

}
