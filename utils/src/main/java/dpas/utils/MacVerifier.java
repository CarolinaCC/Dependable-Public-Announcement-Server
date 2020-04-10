package dpas.utils;

import dpas.grpc.contract.Contract;
import dpas.utils.handler.ErrorGenerator;
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

    public static boolean verifyMac(Contract.SafePostRequest request) throws GeneralSecurityException, IOException {
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] mac = request.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(request);

        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(Contract.ClientHello request) throws GeneralSecurityException, IOException {
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] mac = request.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(request);

        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(PublicKey pubKey, Contract.ServerHello request) throws GeneralSecurityException, IOException {
        byte[] mac = request.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(request);

        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(PublicKey pubKey, Contract.SafePostReply reply) throws GeneralSecurityException, IOException {
        byte[] mac = reply.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(reply);

        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(Contract.SafeRegisterRequest request) throws GeneralSecurityException, IOException {
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] mac = request.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(request);

        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(PublicKey pubKey, Contract.SafeRegisterReply reply) throws GeneralSecurityException, IOException {
        byte[] mac = reply.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(reply);

        return Arrays.equals(digest.digest(content), hash);
    }

    public static boolean verifyMac(PublicKey pubKey, Contract.PostRequest request) throws GeneralSecurityException, IOException {
        byte[] mac = request.getMac().toByteArray();
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, pubKey);
        byte[] hash = cipher.doFinal(mac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] content = ByteUtils.toByteArray(request);

        return Arrays.equals(digest.digest(content), hash);
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
}
