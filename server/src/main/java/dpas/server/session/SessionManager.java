package dpas.server.session;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class SessionManager {

    /**
     * Relationship between keyId and current valid sessionKey
     */
    private Map<String, Session> _sessionKeys;
    private long _keyValidity;

    public SessionManager(long keyValidity) {
        _sessionKeys = new ConcurrentHashMap<>();
        _keyValidity = keyValidity;
        new SessionCleanup(this, keyValidity).run();
    }

    //Testing only
    public SessionManager() {
        _sessionKeys = new ConcurrentHashMap<>();
    }


    public String createSession(long seqNumber, PublicKey pubKey, String sessionNonce, LocalDateTime validity) {

        if (LocalDateTime.now().isAfter(validity)) {
            throw new IllegalArgumentException("Validity of session expired!");
        }
        Session s = new Session(seqNumber, pubKey, sessionNonce, validity);
        String keyId = new SecureRandom().toString();
        _sessionKeys.putIfAbsent(keyId, s);
        return keyId;
    }

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, int sequenceNumber) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //FIXME RACE CONDITIONS
        //FIXME UPDATE SEQUENCE NUMBER
        if (!_sessionKeys.containsKey(keyId))
            throw new IllegalArgumentException("Invalid SessionId");

        Session session = _sessionKeys.get(keyId);

        if (session.isInvalid())
            throw new IllegalArgumentException("Invalid session");

        if (session.get_sequenceNumber() != sequenceNumber + 1)
            throw new IllegalArgumentException("Invalid sequence number");

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, session.get_publicKey());
        byte[] decriptedMac = cipher.doFinal(hmac);

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        if (!Arrays.equals(encodedhash, decriptedMac))
            throw new IllegalArgumentException("Invalid hmac");
    }

    public void cleanup() {
        _sessionKeys.keySet().stream()
                .filter(k -> _sessionKeys.get(k).isInvalid())
                .forEach(k -> _sessionKeys.remove(k));
    }

    public Map<String, Session> getSessionKeys() {
        return _sessionKeys;
    }
}
