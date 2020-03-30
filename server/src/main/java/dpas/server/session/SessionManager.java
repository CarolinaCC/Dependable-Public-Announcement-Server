package dpas.server.session;

import dpas.grpc.contract.Contract;
import dpas.utils.ByteUtils;
import dpas.utils.MacVerifier;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {

    private Map<String, Session> _sessions;
    private long _keyValidity; //in Milliseconds

    public SessionManager(long keyValidity) {
        _sessions = new ConcurrentHashMap<>();
        _keyValidity = keyValidity;
        new Thread(new SessionCleanup(this, keyValidity)).start();
    }

    //Testing only
    public SessionManager() {
        _sessions = new ConcurrentHashMap<>();
    }

    public long createSession(PublicKey pubKey, String sessionNonce) throws SessionException {
        long seq = new SecureRandom().nextLong();
        Session s = new Session(seq, pubKey, sessionNonce, LocalDateTime.now().plusNanos(_keyValidity * 1000000));
        var session = _sessions.putIfAbsent(sessionNonce, s);
        if (session != null) {
            throw new SessionException("Session already exists!");
        }
        return seq;
    }

    public void removeSession(String sessionNonce) {
        _sessions.remove(sessionNonce);
    }


    public long validateSessionRequest(Contract.SafeRegisterRequest request) throws GeneralSecurityException, IOException, SessionException {
        String nonce = request.getSessionNonce();
        return validateSessionRequest(nonce, request.getMac().toByteArray(), ByteUtils.toByteArray(request), request.getSeq());
    }


    public void validateSessionRequest(Contract.GoodByeRequest request) throws GeneralSecurityException, IOException, SessionException {
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        String sessionNonce = request.getSessionNonce();
        long seq = request.getSeq();
        validateSessionRequest(sessionNonce, mac, content, seq);
    }

    public long validateSessionRequest(Contract.SafePostRequest request) throws GeneralSecurityException, IOException, SessionException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        String sessionNonce = request.getSessionNonce();
        long seq = request.getSeq();
        return validateSessionRequest(sessionNonce, mac, content, seq, key);
    }

    public long validateSessionRequest(String sessionNonce, byte[] mac, byte[] content, long sequenceNumber) throws GeneralSecurityException, SessionException, IOException {

        Session session = _sessions.getOrDefault(sessionNonce, null);

        if (session == null)
            throw new SessionException("Invalid Session, doesn't exist or has expired");

        synchronized (session) {

            if (session.isInvalid())
                throw new SessionException("Session is expired");

            if (session.getSequenceNumber() + 1 != sequenceNumber)
                throw new SessionException("Invalid sequence number");

            return validateRequest(mac, content, session);
        }
    }


    public long validateSessionRequest(String sessionNonce, byte[] mac, byte[] content, long sequenceNumber, PublicKey pubKey) throws GeneralSecurityException, SessionException, IOException {

        Session session = _sessions.getOrDefault(sessionNonce, null);

        if (session == null)
            throw new SessionException("Invalid Session, doesn't exist or has expired");

        synchronized (session) {

            if (session.isInvalid())
                throw new SessionException("Session is expired");

            if (session.getSequenceNumber() + 1 != sequenceNumber)
                throw new SessionException("Invalid sequence number");

            if (!Arrays.equals(session.getPublicKey().getEncoded(), pubKey.getEncoded()))
                throw new SessionException("Invalid Public Key for request");

            return validateRequest(mac, content, session);
        }
    }


    private long validateRequest(byte[] mac, byte[] content, Session session) throws GeneralSecurityException, SessionException, IOException {

        if (!MacVerifier.verifyMac(session.getPublicKey(), content, mac))
            throw new SessionException("Invalid mac");

        session.nextSequenceNumber();
        //Update Validity
        session.setValidity(LocalDateTime.now().plusNanos(_keyValidity * 1000));
        return session.getSequenceNumber();
    }

    public void cleanup() {
        _sessions.keySet().stream()
                .filter(k -> _sessions.get(k).isInvalid())
                .forEach(this::removeSession);
    }

    public Map<String, Session> getSessions() {
        return _sessions;
    }
}
