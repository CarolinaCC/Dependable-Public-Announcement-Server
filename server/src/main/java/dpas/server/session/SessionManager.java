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
    private long _sessionTime; //in Milliseconds
    private long _newSessionTime; //Sessions are short before the first request

    public SessionManager(long sessionTime) {
        _sessions = new ConcurrentHashMap<>();
        _sessionTime = sessionTime;
        _newSessionTime = sessionTime;
        new Thread(new SessionCleanup(this, sessionTime)).start();
    }


    public SessionManager(long sessionTime, long newSessionTime) {
        _sessions = new ConcurrentHashMap<>();
        _sessionTime = sessionTime;
        _newSessionTime = newSessionTime;
        new Thread(new SessionCleanup(this, sessionTime)).start();
    }

    //Testing purposes only
    public SessionManager() {
        _sessions = new ConcurrentHashMap<>();
    }

    public long createSession(PublicKey pubKey, String sessionNonce) throws SessionException {
        long seq = new SecureRandom().nextLong();
        Session s = new Session(seq, pubKey, sessionNonce, LocalDateTime.now().plusNanos(_newSessionTime * 1000000));
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
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        String nonce = request.getSessionNonce();
        byte[] content = ByteUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        long seq = request.getSeq();
        return validateSessionRequest(nonce, mac, content, seq, key);
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
                throw new IllegalArgumentException("Invalid Public Key for request");

            return validateRequest(mac, content, session);
        }
    }


    private long validateRequest(byte[] mac, byte[] content, Session session) throws GeneralSecurityException, SessionException, IOException {

        if (!MacVerifier.verifyMac(session.getPublicKey(), content, mac))
            throw new IllegalArgumentException("Invalid mac");

        session.nextSequenceNumber();
        //Update Validity
        session.setValidity(LocalDateTime.now().plusNanos(_sessionTime * 1000000));
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
