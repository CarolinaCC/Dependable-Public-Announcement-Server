package dpas.utils;

import dpas.grpc.contract.Contract;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public class MacGenerator {

    public static byte[] generateMac(String sessionNonce, long seq, PrivateKey privKey) throws IOException, GeneralSecurityException {
        byte[] content = ByteUtils.toByteArray(sessionNonce, seq);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);
    }

    public static byte[] generateMac(String sessionNonce, PublicKey publicKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
        byte[] content = ByteUtils.toByteArray(sessionNonce, publicKey);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);
    }

    public static byte[] generateMac(String sessionNonce, long seq, PublicKey pubKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
        byte[] content = ByteUtils.toByteArray(sessionNonce, seq, pubKey);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);
    }

    public static byte[] generateMac(long seq, String nonce, PublicKey pubKey, byte[] message,
                                     byte[] signature, List<String> references, PrivateKey privKey) throws IOException, GeneralSecurityException {
        byte[] content = ByteUtils.toByteArray(seq, nonce, pubKey, message, signature, references);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);

    }


    public static byte[] generateMac(Contract.SafePostRequest request, PrivateKey privKey) throws IOException, GeneralSecurityException {
        byte[] content = ByteUtils.toByteArray(request);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        byte[] mac = cipher.doFinal(hash);
        return mac;
    }
}
