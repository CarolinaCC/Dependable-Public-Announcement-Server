package dpas.server.session;

import java.security.Key;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {
    /**Relationship between keyId and current valid sessionKey*/
    private Map<String, Key> _sessionKeys = new ConcurrentHashMap<>();
    /**Relationship between keyId and sessionKey not yet validated*/
    private Map<String, Key> _futureKeys = new ConcurrentHashMap<>();
    /**Relationship between keyId and current sequence number for session*/
    private Map<String, Integer> _sessionSequenceNumber = new ConcurrentHashMap<>();
    /**Relationship between keyId and current sequence number for future session*/
    private Map<String, Integer> _futureSequenceNumber = new ConcurrentHashMap<>();

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, int sequenceNumber) {

    }

    /**
     * Validates an hmac for a future session
     */
    public void validateHmacForNewSession(String keyId, byte[] hmac, byte[] content, int sequenceNumber) {

    }

    //TODO: CLEANUP DAS SESSIONKEYS

}
