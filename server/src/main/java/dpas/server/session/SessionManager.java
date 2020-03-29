package dpas.server.session;

import java.security.Key;
import java.util.Map;
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

    public long createSession() {
        //TODO
        return 0L;
    }

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, int sequenceNumber) {
        //TODO CAROLINA
    }

    public void cleanup() {
        _sessionKeys.keySet().stream()
                .filter(k -> _sessionKeys.get(k).isInvalid())
                .forEach(k -> _sessionKeys.remove(k));
    }
}
