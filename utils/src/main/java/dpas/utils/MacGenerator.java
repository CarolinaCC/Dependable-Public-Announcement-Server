package dpas.utils;

import dpas.grpc.contract.Contract;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.*;
import java.util.List;

public class MacGenerator {

    public static byte[] generateMac(String sessionNonce, long seq, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(sessionNonce, seq), privKey);
    }

    public static byte[] generateMac(String sessionNonce, PublicKey publicKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(sessionNonce, publicKey), privKey);
    }

    public static byte[] generateMac(String sessionNonce, long seq, PublicKey pubKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
       return generateMac(ByteUtils.toByteArray(sessionNonce, seq, pubKey), privKey);
    }

    public static byte[] generateMac(long seq, String nonce, PublicKey pubKey, byte[] message,
                                     byte[] signature, List<String> references, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(seq, nonce, pubKey, message, signature, references), privKey);
    }

    public static byte[] generateMac(Contract.SafePostRequest request, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(request), privKey);
    }

    private static byte[] generateMac(byte[] content, PrivateKey privKey) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);
    }
}
