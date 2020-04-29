package dpas.utils.auth;

import dpas.grpc.contract.Contract;
import dpas.utils.Constants;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import static dpas.common.domain.utils.CryptographicConstants.*;

public final class MacGenerator {

    private MacGenerator() {}

    public static byte[] generateMac(PublicKey pubKey, PrivateKey privKey) throws GeneralSecurityException {
        return generateMac(pubKey.getEncoded(), privKey);
    }

    public static byte[] generateMac(String nonce, long seq, PublicKey pubKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(nonce, seq, pubKey), privKey);
    }

    public static byte[] generateMac(Contract.ReadRequest request, int announcementCount, PrivateKey privKey) throws GeneralSecurityException, IOException {
        return generateMac(ByteUtils.toByteArray(request, announcementCount), privKey);
    }

    public static byte[] generateMac(Contract.Announcement request, PrivateKey privKey) throws GeneralSecurityException {
        return generateMac(ByteUtils.toByteArray(request), privKey);
    }

    public static byte[] generateMac(byte[] content, PrivateKey privKey) throws GeneralSecurityException {
        MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
        byte[] hash = digest.digest(content);

        Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, privKey);
        return cipher.doFinal(hash);
    }

}
