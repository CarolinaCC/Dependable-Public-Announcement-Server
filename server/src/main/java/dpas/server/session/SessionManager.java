package dpas.server.session;

import java.security.Key;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    /**Relationship between keyId and current valid sessionKey*/
    private Map<String, Session> _sessionKeys = new ConcurrentHashMap<>();

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

    //TODO: CLEANUP DAS SESSIONKEYS

}
