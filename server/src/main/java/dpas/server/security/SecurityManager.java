package dpas.server.security;

import dpas.grpc.contract.Contract;
import dpas.server.security.exception.IllegalMacException;
import dpas.utils.auth.ByteUtils;
import dpas.utils.auth.MacVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class SecurityManager {


    public void validateRequest(Contract.RegisterRequest request) throws GeneralSecurityException, IllegalMacException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        validateRequest(mac, content, publicKey);
    }

    private void validateRequest(byte[] mac, byte[] content, PublicKey key) throws IllegalMacException {
        if (!MacVerifier.verifyMac(key, content, mac))
            throw new IllegalMacException("Could not validate request");

    }
}
