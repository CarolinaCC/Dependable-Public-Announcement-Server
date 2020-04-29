package dpas.server.security;

import dpas.grpc.contract.Contract;
import dpas.server.security.exception.IllegalMacException;
import dpas.utils.auth.ByteUtils;
import dpas.utils.auth.MacVerifier;
import org.apache.commons.lang3.ArrayUtils;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Map;

import static dpas.common.domain.utils.CryptographicConstants.ASYMMETRIC_KEY_ALGORITHM;
import static dpas.utils.Constants.ECHO;
import static dpas.utils.Constants.READY;

public final class SecurityManager {

    private SecurityManager() {
    }

    public static void validateRequest(Contract.RegisterRequest request) throws GeneralSecurityException, IllegalMacException {
        PublicKey publicKey = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        validateRequest(mac, content, publicKey);
    }

    private static void validateRequest(byte[] mac, byte[] content, PublicKey key) throws IllegalMacException {
        if (!MacVerifier.verifyMac(key, content, mac))
            throw new IllegalMacException("Could not validate request");

    }

    public static void validateRequest(Contract.EchoRegister request, Map<String, PublicKey> serverKeys) throws GeneralSecurityException, IllegalMacException {
        validateRequest(request.getRequest());
        var pubKey = serverKeys.get(request.getServerKey());
        if (pubKey == null) {
            throw new IllegalMacException("Ilegal Server Key");
        }
        var mac = request.getMac().toByteArray();
        var content = ArrayUtils.addAll(request.getRequest().getMac().toByteArray(), ECHO);
        if (!MacVerifier.verifyMac(pubKey, content, mac)) {
            throw new IllegalMacException("Invalid Mac For Request");
        }
    }

    public static void validateRequest(Contract.ReadyRegister request, Map<String, PublicKey> serverKeys) throws GeneralSecurityException, IllegalMacException {
        validateRequest(request.getRequest());
        var pubKey = serverKeys.get(request.getServerKey());
        if (pubKey == null) {
            throw new IllegalMacException("Ilegal Server Key");
        }
        var mac = request.getMac().toByteArray();
        var content = ArrayUtils.addAll(request.getRequest().getMac().toByteArray(), READY);
        if (!MacVerifier.verifyMac(pubKey, content, mac)) {
            throw new IllegalMacException("Invalid Mac For Request");
        }
    }

    public static void validateAnnouncement(Contract.ReadyAnnouncement request, Map<String, PublicKey> serverKeys) throws GeneralSecurityException, IllegalMacException {
        var pubKey = serverKeys.get(request.getServerKey());
        if (pubKey == null) {
            throw new IllegalMacException("Ilegal Server Key");
        }
        var mac = request.getMac().toByteArray();
        var content = ArrayUtils.addAll(request.getRequest().getSignature().toByteArray(), READY);
        if (!MacVerifier.verifyMac(pubKey, content, mac)) {
            throw new IllegalMacException("Invalid Mac For Request");
        }
    }

    public static void validateAnnouncement(Contract.EchoAnnouncement request, Map<String, PublicKey> serverKeys) throws GeneralSecurityException, IllegalMacException {
        var pubKey = serverKeys.get(request.getServerKey());
        if (pubKey == null) {
            throw new IllegalMacException("Ilegal Server Key");
        }
        var mac = request.getMac().toByteArray();
        var content = ArrayUtils.addAll(request.getRequest().getSignature().toByteArray(), ECHO);
        if (!MacVerifier.verifyMac(pubKey, content, mac)) {
            throw new IllegalMacException("Invalid Mac For Request");
        }
    }
}
