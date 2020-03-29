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
    private Map<String, Session> _sessionKeys = new ConcurrentHashMap<>();

    public String createSession(long seqNumber, PublicKey pubKey, String sessionNonce, LocalDateTime validity) {

        Session s = new Session(seqNumber, pubKey, sessionNonce, validity);
        String keyId = new SecureRandom().toString();
        _sessionKeys.putIfAbsent(keyId, s);
        return keyId;
    }

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, int sequenceNumber) {
        //TODO CAROLINA
    }

    //TODO: CLEANUP DAS SESSIONKEYS

}
