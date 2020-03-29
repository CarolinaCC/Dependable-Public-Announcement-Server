package dpas.server.session;

import java.security.Key;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    /**Relationship between keyId and current valid sessionKey*/
    private Map<String, Session> _sessionKeys;
    private long _keyValidity;

    public SessionManager(long keyValidity) {
        _sessionKeys = new ConcurrentHashMap<>();
        _keyValidity = keyValidity;
        new SessionCleanup(this, keyValidity).run();
    }

    public String createSession(long seqNumber, PublicKey pubKey, String sessionNonce, int validity) {

        LocalDateTime val = LocalDateTime.now().plusSeconds(validity / 1000);
        Session s = new Session(seqNumber, pubKey, sessionNonce, val);
        String keyId = new SecureRandom().toString();
        var session = _sessionKeys.putIfAbsent(keyId, s);
        if (session != null) {
            throw new IllegalArgumentException("Session already exists!");
        }
        return keyId;
    }

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, int sequenceNumber) {
        if (!_sessionKeys.containsKey(keyId))
            throw new IllegalArgumentException("Invalid SessionId");


        Session session = _sessionKeys.get(keyId);

        if (session.isInvalid())
            throw new IllegalArgumentException("Invalid session");

        if (session.get_sequenceNumber() != sequenceNumber + 1)
            throw new IllegalArgumentException("Invalid sequence number");



        //TODO CAROLINA
    }

    public void cleanup() {
        _sessionKeys.keySet().stream()
                .filter(k -> _sessionKeys.get(k).isInvalid())
                .forEach(k -> _sessionKeys.remove(k));
    }
}
