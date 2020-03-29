package dpas.server.session;

import java.security.Key;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    /**Relationship between keyId and current valid sessionKey*/
    private Map<String, Session> _sessionKeys;

    public SessionManager() {
        _sessionKeys = new ConcurrentHashMap<>();
        new SessionCleanup()
    }

    public long createSession() {
        //TODO
        return 0L;
    }

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, int sequenceNumber) {
        if (!_sessionKeys.containsKey(keyId)) {
            throw new IllegalArgumentException("Invalid SessionId");
        }

        Session session = _sessionKeys.get(keyId);

        if (session.get_sequenceNumber() != sequenceNumber + 1) {
            throw new IllegalArgumentException("Invalid SessionId");
        }


        //TODO CAROLINA
    }


    public void cleanup() {
        _sessionKeys.keySet().stream()
                .filter(k -> _sessionKeys.get(k).isInvalid())
                .forEach(k -> _sessionKeys.remove(k));
    }
}
