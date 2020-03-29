package dpas.server.session;

import dpas.utils.MacGenerator;
import dpas.utils.MacVerifier;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.temporal.TemporalUnit;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

public class SessionManager {

    /**
     * Relationship between keyId and current valid sessionKey
     */
    private Map<String, Session> _sessions;
    private long _keyValidity;

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
        Session s = new Session(seq, pubKey, sessionNonce, LocalDateTime.now().plusNanos(_keyValidity * 1000));
        var session = _sessions.putIfAbsent(sessionNonce, s);
        if (session != null) {
            throw new SessionException("Session already exists!");
        }
        return seq;
    }

    public void removeSession(String sessionNonce) {
        _sessions.remove(sessionNonce);
    }

    /**
     * Validates an hmac for a valid session
     */
    public long validateSessionRequest(String sessionNonce, byte[] mac, byte[] content, long sequenceNumber, PublicKey pubKey) throws GeneralSecurityException, SessionException, IOException {

        Session session = _sessions.getOrDefault(sessionNonce, null);

        if (session == null)
            throw new SessionException("Invalid Session");

        if (session.isInvalid())
            throw new SessionException("Session Expired");

        if (session.getSequenceNumber() + 1 != sequenceNumber)
            throw new SessionException("Invalid sequence number");

        if (!Arrays.equals(session.getPublicKey().getEncoded(), pubKey.getEncoded())) {
            throw new SessionException("Invalid Public Key for request");
        }

        return validateRequest(mac, content, session);
    }

    public long validateSessionRequest(String sessionNonce, byte[] mac, byte[] content, long sequenceNumber) throws GeneralSecurityException, SessionException, IOException {

        Session session = _sessions.getOrDefault(sessionNonce, null);

        if (session == null)
            throw new SessionException("Invalid SessionId");

        if (session.isInvalid())
            throw new SessionException("Invalid session");

        if (session.getSequenceNumber() + 1 != sequenceNumber)
            throw new SessionException("Invalid sequence number");

        return validateRequest(mac, content, session);
    }

    private long validateRequest(byte[] mac, byte[] content, Session session) throws GeneralSecurityException, SessionException, IOException {

        if (!MacVerifier.verifyMac(session.getPublicKey(), content, mac))
            throw new SessionException("Invalid hmac");

        session.nextSequenceNumber();
        //Update Validity
        session.setValidity(LocalDateTime.now().plusNanos(_keyValidity * 1000));
        return session.getSequenceNumber();
    }

    public void cleanup() {
        _sessions.keySet().stream()
                .filter(k -> _sessions.get(k).isInvalid())
                .forEach(k -> _sessions.remove(k));
    }

    public Map<String, Session> getSessionKeys() {
        return _sessions;
    }
}
