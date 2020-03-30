package dpas.utils;

import dpas.grpc.contract.Contract;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;

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

    public static byte[] generateMac(String content, PrivateKey privKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content.getBytes());

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
