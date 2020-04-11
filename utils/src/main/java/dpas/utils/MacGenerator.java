package dpas.utils;

import dpas.grpc.contract.Contract;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class MacGenerator {

    public static byte[] generateMac(PublicKey pubKey, PrivateKey privKey) throws GeneralSecurityException {
        return generateMac(pubKey.getEncoded(), privKey);
    }

    public static byte[] generateMac(String nonce, long seq, PublicKey pubKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(nonce, seq, pubKey), privKey);
    }

    public static byte[] generateMac(Contract.ReadRequest request, List<Contract.Announcement> reply, PrivateKey privKey) throws GeneralSecurityException, IOException {
        return generateMac(ByteUtils.toByteArray(request, reply), privKey);
    }

    public static byte[] generateMac(Contract.PostRequest request, PrivateKey privKey) throws GeneralSecurityException, IOException {
        return generateMac(ByteUtils.toByteArray(request), privKey);
    }

    public static byte[] generateMac(long seq, PublicKey pubKey, String message, byte[] signature, Set<String> references, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(seq, pubKey, message, signature, references), privKey);
    }

    public static byte[] generateMac(byte[] content, PrivateKey privKey) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);
    }

}
