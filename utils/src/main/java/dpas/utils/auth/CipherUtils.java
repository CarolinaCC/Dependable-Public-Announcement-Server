package dpas.utils.auth;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class CipherUtils {

    public static byte[] decipher(byte[] content, PrivateKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(content);
    }

    public static byte[] decodeAndDecipher(String content, PrivateKey key) throws GeneralSecurityException {
        return decipher(Base64.getDecoder().decode(content), key);
    }


    public static byte[] cipher(byte[] content, PublicKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(content);
    }

    public static String cipherAndEncode(byte[] content, PublicKey key) throws GeneralSecurityException {
        return Base64.getEncoder().encodeToString(cipher(content, key));
    }

    public static String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static PublicKey keyFromBytes(byte[] key) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(key));
    }

    public static PrivateKey privKeyFromBytes(byte[] key) throws GeneralSecurityException {
        return KeyFactory.getInstance("RSA").generatePrivate(new X509EncodedKeySpec(key));
    }
}
