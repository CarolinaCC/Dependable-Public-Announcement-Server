package dpas.utils;

import dpas.grpc.contract.Contract;
import io.grpc.Metadata;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class MacVerifier {

    public static boolean verifyMac(Contract.RegisterRequest request, Contract.MacReply reply, PublicKey serverKey) throws GeneralSecurityException {
        byte[] mac = reply.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, serverKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = digest.digest(request.getMac().toByteArray());

        return Arrays.equals(content, hash);
    }

    public static boolean verifyMac(PublicKey pubKey, byte[] content, byte[] mac) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(PublicKey key, StatusRuntimeException e) {
        try {
            Metadata data = e.getTrailers();
            byte[] content = ArrayUtils.addAll(data.get(ErrorGenerator.contentKey), e.getMessage().getBytes());
            byte[] mac = data.get(ErrorGenerator.macKey);
            return MacVerifier.verifyMac(key, content, mac);
        } catch (GeneralSecurityException ex) {
            return false;
        }
    }

    public static boolean verifyMac(PublicKey pubKey, Contract.MacReply reply, Contract.Announcement request) throws GeneralSecurityException {
        byte[] content = request.getSignature().toByteArray();
        byte[] mac = reply.getMac().toByteArray();
        return verifyMac(pubKey, content, mac);
    }

    public static boolean verifyMac(PublicKey pubKey, Contract.GetSeqReply reply, Contract.GetSeqRequest request) throws GeneralSecurityException, IOException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] content = ByteUtils.toByteArray(request.getNonce(), reply.getSeq(), key);
        byte[] mac = reply.getMac().toByteArray();
        return verifyMac(pubKey, content, mac);
    }

}
