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
        new Thread(new SessionCleanup(this, keyValidity)).start();
    }

    //Testing only
    public SessionManager() {
        _sessionKeys = new ConcurrentHashMap<>();
    }

    public long createSession(PublicKey pubKey, String sessionNonce) {

        Session s = new Session(new SecureRandom().nextLong(), pubKey, sessionNonce, LocalDateTime.now().plusMinutes(_keyValidity));
        var session = _sessionKeys.putIfAbsent(sessionNonce, s);
        if (session != null) {
            throw new IllegalArgumentException("Session already exists!");
        }
        return s.get_sequenceNumber();
    }

    /**
     * Validates an hmac for a valid session
     */
    public void validateSessionRequest(String keyId, byte[] hmac, byte[] content, long sequenceNumber) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //FIXME RACE CONDITIONS
        //FIXME UPDATE SEQUENCE NUMBER

        if (!_sessionKeys.containsKey(keyId))
            throw new IllegalArgumentException("Invalid SessionId");

        Session session = _sessionKeys.get(keyId);

        if (session.isInvalid())
            throw new IllegalArgumentException("Invalid session");

        if (session.get_sequenceNumber() + 1 != sequenceNumber)
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
