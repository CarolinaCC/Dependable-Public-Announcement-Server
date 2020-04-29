package dpas.common.domain.utils;

public final class CryptographicConstants {

    public static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static final String DIGEST_ALGORITHM = "SHA-256";
    public static final String ASYMMETRIC_KEY_ALGORITHM = "RSA";
    public static final String CIPHER_ALGORITHM = "RSA/ECB/PKCS1Padding";

    private CryptographicConstants() {
    }
}
