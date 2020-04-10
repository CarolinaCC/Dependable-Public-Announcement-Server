package dpas.server.session;

import dpas.grpc.contract.Contract;
import dpas.server.session.exception.IllegalMacException;
import dpas.server.session.exception.SessionException;
import dpas.utils.ByteUtils;
import dpas.utils.MacVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

public class SessionManager {


    public void validateSessionRequest(Contract.RegisterRequest request) throws GeneralSecurityException, IOException, IllegalMacException {
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        if (!MacVerifier.verifyMac(publicKey, content, mac))
            throw new IllegalMacException("Invalid mac");
    }

    public void validateSessionRequest(Contract.PostRequest request, long currSeq) throws GeneralSecurityException, IOException, SessionException, IllegalMacException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        long seq = request.getSeq();
        validateSessionRequest(mac, content, seq, key, currSeq);
    }

    public void validateSessionRequest(byte[] mac, byte[] content, long seq, PublicKey pubKey, long currSeq) throws GeneralSecurityException, SessionException, IllegalMacException {
        if (currSeq + 1 != seq)
            throw new SessionException("Invalid sequence number");

        validateRequest(mac, content, pubKey);
    }

    private void validateRequest(byte[] mac, byte[] content, PublicKey key) throws GeneralSecurityException, IllegalMacException {
        if (!MacVerifier.verifyMac(key, content, mac))
            throw new IllegalMacException("Invalid mac");

    }
}
