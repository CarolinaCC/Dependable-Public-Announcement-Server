package dpas.utils.auth;

import dpas.grpc.contract.Contract;
import io.grpc.Metadata;
import io.grpc.StatusRuntimeException;
import org.apache.commons.lang3.ArrayUtils;

import javax.crypto.Cipher;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.util.Arrays;

public class MacVerifier {

    public static boolean verifyMac(Contract.RegisterRequest request, Contract.MacReply reply, PublicKey serverKey) {
        try {
            byte[] mac = reply.getMac().toByteArray();
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, serverKey);
            byte[] hash = cipher.doFinal(mac);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] content = digest.digest(request.getMac().toByteArray());

            return Arrays.equals(content, hash);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static boolean verifyMac(PublicKey pubKey, byte[] content, byte[] mac) {
        try {
            Cipher cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.DECRYPT_MODE, pubKey);
            byte[] hash = cipher.doFinal(mac);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Arrays.equals(digest.digest(content), hash);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static boolean verifyMac(PublicKey key, StatusRuntimeException e) {
        Metadata data = e.getTrailers();
        byte[] content = ArrayUtils.addAll(data.get(ErrorGenerator.contentKey), e.getMessage().getBytes());
        byte[] mac = data.get(ErrorGenerator.macKey);
        return MacVerifier.verifyMac(key, content, mac);

    }

    public static boolean verifyMac(PublicKey pubKey, Contract.MacReply reply, Contract.Announcement request) {
        byte[] content = request.getSignature().toByteArray();
        byte[] mac = reply.getMac().toByteArray();
        return verifyMac(pubKey, content, mac);
    }
}
