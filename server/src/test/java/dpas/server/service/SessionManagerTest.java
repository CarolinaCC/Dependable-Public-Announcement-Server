package dpas.server.service;

import dpas.server.session.Session;
import dpas.server.session.SessionException;
import dpas.server.session.SessionManager;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;
import java.time.LocalDateTime;

import static org.junit.Assert.*;

public class SessionManagerTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private SessionManager _manager;
    private static final String SESSION_NONCE = "NONCE";
    private static final String SESSION_NONCE2 = "NONCE2";
    private static final String SESSION_NONCE3 = "NONCE3";
    private static final String SESSION_NONCE4 = "NONCE4";
    private static final String SESSION_NONCE5 = "NONCE5";
    private static final String SESSION_NONCE6 = "NONCE6";
    private PublicKey _pubKey;
    private static final int VALIDITY = 5000;

    @Before
    public void setup() throws NoSuchAlgorithmException {
        _manager = new SessionManager();

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();

    }

    @Test
    public void cleanupTest() throws NoSuchAlgorithmException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        Session invalidSession = new Session(0, pubKey, SESSION_NONCE2, LocalDateTime.now().minusHours(1));
        _manager.getSessionKeys().put(SESSION_NONCE, validSession);
        _manager.getSessionKeys().put(SESSION_NONCE2, invalidSession);
        _manager.cleanup();
        assertEquals(_manager.getSessionKeys().size(), 1);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getSequenceNumber(), 0);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getSessionNonce(), SESSION_NONCE);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getValidity(), validTime);
    }

    @Test
    public void multipleSessionsCleanupTest() throws NoSuchAlgorithmException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE, validSession);
        validSession = new Session(1, pubKey, SESSION_NONCE2, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE2, validSession);
        validSession = new Session(2, pubKey, SESSION_NONCE3, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE3, validSession);
        validSession = new Session(3, pubKey, SESSION_NONCE4, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE4, validSession);
        validSession = new Session(4, pubKey, SESSION_NONCE5, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE5, validSession);


        Session invalidSession = new Session(0, pubKey, SESSION_NONCE6, LocalDateTime.now().minusHours(1));
        _manager.getSessionKeys().put(SESSION_NONCE6, invalidSession);
        _manager.cleanup();
        assertEquals(_manager.getSessionKeys().size(), 5);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getSequenceNumber(), 0);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getSessionNonce(), SESSION_NONCE);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getValidity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE2).getSequenceNumber(), 1);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE2).getSessionNonce(), SESSION_NONCE2);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE2).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE2).getValidity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE3).getSequenceNumber(), 2);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE3).getSessionNonce(), SESSION_NONCE3);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE3).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE3).getValidity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE4).getSequenceNumber(), 3);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE4).getSessionNonce(), SESSION_NONCE4);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE4).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE4).getValidity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE5).getSequenceNumber(), 4);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE5).getSessionNonce(), SESSION_NONCE5);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE5).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE5).getValidity(), validTime);

    }

    @Test
    public void SessionCleanupTest() throws NoSuchAlgorithmException, InterruptedException {
        LocalDateTime invalidTime = LocalDateTime.now().plusSeconds(1);
        _manager = new SessionManager(2000);
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();

        Session invalidSession = new Session(0, pubKey, SESSION_NONCE, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE, invalidSession);
        invalidSession = new Session(1, pubKey, SESSION_NONCE2, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE2, invalidSession);
        invalidSession = new Session(2, pubKey, SESSION_NONCE3, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE3, invalidSession);
        invalidSession = new Session(3, pubKey, SESSION_NONCE4, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE4, invalidSession);
        invalidSession = new Session(4, pubKey, SESSION_NONCE5, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE5, invalidSession);
        invalidSession = new Session(0, pubKey, SESSION_NONCE6, LocalDateTime.now().minusHours(1));
        _manager.getSessionKeys().put(SESSION_NONCE6, invalidSession);
        Thread.sleep(3000);
        assertEquals(_manager.getSessionKeys().size(), 0);
    }

    @Test
    public void SessionCleanupTestSomeValid() throws NoSuchAlgorithmException, InterruptedException {
        LocalDateTime invalidTime = LocalDateTime.now().plusSeconds(1);
        LocalDateTime validTime = LocalDateTime.now().plusSeconds(6);
        _manager = new SessionManager(2000);
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();

        Session invalidSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE, invalidSession);
        invalidSession = new Session(1, pubKey, SESSION_NONCE2, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE2, invalidSession);
        invalidSession = new Session(2, pubKey, SESSION_NONCE3, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE3, invalidSession);
        invalidSession = new Session(3, pubKey, SESSION_NONCE4, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE4, invalidSession);
        invalidSession = new Session(4, pubKey, SESSION_NONCE5, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE5, invalidSession);
        invalidSession = new Session(0, pubKey, SESSION_NONCE6, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE6, invalidSession);
        Thread.sleep(3000);
        assertEquals(_manager.getSessionKeys().size(), 2);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE).getPublicKey().getEncoded(), pubKey.getEncoded());
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE2).getPublicKey().getEncoded(), pubKey.getEncoded());
    }


    @Test
    public void multipleinvalidSessionsCleanupTest() throws NoSuchAlgorithmException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime invalidTime = LocalDateTime.now().minusHours(1);

        Session invalidSession = new Session(0, pubKey, SESSION_NONCE, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE, invalidSession);
        invalidSession = new Session(1, pubKey, SESSION_NONCE2, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE2, invalidSession);
        invalidSession = new Session(2, pubKey, SESSION_NONCE3, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE3, invalidSession);
        invalidSession = new Session(3, pubKey, SESSION_NONCE4, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE4, invalidSession);
        invalidSession = new Session(4, pubKey, SESSION_NONCE5, invalidTime);
        _manager.getSessionKeys().put(SESSION_NONCE5, invalidSession);
        invalidSession = new Session(0, pubKey, SESSION_NONCE6, LocalDateTime.now().minusHours(1));
        _manager.getSessionKeys().put(SESSION_NONCE6, invalidSession);
        _manager.cleanup();
        assertEquals(_manager.getSessionKeys().size(), 0);
    }


    @Test
    public void createSessionValid() throws SessionException {

        SessionManager manager = new SessionManager(5);
        manager.createSession(_pubKey, SESSION_NONCE);

        assertEquals(manager.getSessionKeys().get(SESSION_NONCE).getSessionNonce(), SESSION_NONCE);
        assertArrayEquals(manager.getSessionKeys().get(SESSION_NONCE).getPublicKey().getEncoded(), _pubKey.getEncoded());
    }

    @Test(expected = SessionException.class)
    public void createSameSessionNonce() throws SessionException {

        SessionManager manager = new SessionManager(5);
        manager.createSession(_pubKey, SESSION_NONCE);
        manager.createSession(_pubKey, SESSION_NONCE);
    }

    @Test
    public void validateSessionRequestTest() throws GeneralSecurityException, SessionException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE, validSession);

        long sequenceNumber = validSession.getSequenceNumber() + 1;
        String keyId = validSession.getSessionNonce();
        byte[] content = "message".getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] hmac = cipher.doFinal(encodedhash);

        _manager.validateSessionRequest(keyId, hmac, content, sequenceNumber);
        assertNotEquals(_manager.getSessionKeys().get(SESSION_NONCE).getValidity(), validTime);
    }

    @Test
    public void invalidKeySessionRequestTest() throws GeneralSecurityException, SessionException {
        exception.expect(SessionException.class);
        //exception.expectMessage("Invalid SessionId");
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE, validSession);

        long sequenceNumber = validSession.getSequenceNumber() + 1;
        String keyId = validSession.getSessionNonce();
        byte[] content = "message".getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] hmac = cipher.doFinal(encodedhash);

        keyPair = keyFactory.generateKeyPair();
        pubKey = keyPair.getPublic();
        _manager.validateSessionRequest(keyId, hmac, content, sequenceNumber, pubKey);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).getValidity(), validTime);
    }


    @Test

    public void invalidSessionIdValidateSessionRequestTest() throws GeneralSecurityException, SessionException {
        exception.expect(SessionException.class);
        exception.expectMessage("Invalid SessionId");

        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        _manager.getSessionKeys().put(SESSION_NONCE, validSession);

        long sequenceNumber = validSession.getSequenceNumber() + 1;
        String keyId = SESSION_NONCE5;
        byte[] content = "message".getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] hmac = cipher.doFinal(encodedhash);

        _manager.validateSessionRequest(keyId, hmac, content, sequenceNumber);
    }

    @Test
    public void invalidSeqNumbergvalidateSessionRequestTest() throws GeneralSecurityException, SessionException {
        exception.expect(SessionException.class);
        exception.expectMessage("Invalid sequence number");

        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);

        _manager.getSessionKeys().put(SESSION_NONCE, validSession);

        long sequenceNumber = validSession.getSequenceNumber() + 1;
        String keyId = validSession.getSessionNonce();
        byte[] content = "message".getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] hmac = cipher.doFinal(encodedhash);

        _manager.validateSessionRequest(keyId, hmac, content, sequenceNumber - 1);
    }

    @Test
    public void invalidHMACvalidateSessionRequestTest() throws GeneralSecurityException, SessionException {
        exception.expect(SessionException.class);
        exception.expectMessage("Invalid hmac");

        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime = LocalDateTime.now().plusHours(1);

        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);

        _manager.getSessionKeys().put(SESSION_NONCE, validSession);

        long sequenceNumber = validSession.getSequenceNumber() + 1;
        String keyId = validSession.getSessionNonce();
        byte[] content = "message".getBytes();


        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest("wrong message".getBytes());

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] hmac = cipher.doFinal(encodedhash);

        _manager.validateSessionRequest(keyId, hmac, content, sequenceNumber);
    }


    @Test
    public void invalidSessionvalidateSessionRequestTest() throws GeneralSecurityException, SessionException {
        exception.expect(SessionException.class);
        exception.expectMessage("Invalid session");

        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();

        Session invalidSession = new Session(0, pubKey, SESSION_NONCE6, LocalDateTime.now().minusHours(1));

        _manager.getSessionKeys().put(SESSION_NONCE6, invalidSession);

        long sequenceNumber = invalidSession.getSequenceNumber() + 1;
        String keyId = invalidSession.getSessionNonce();
        byte[] content = "message".getBytes();

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedhash = digest.digest(content);

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
        byte[] hmac = cipher.doFinal(encodedhash);

        _manager.validateSessionRequest(keyId, hmac, content, sequenceNumber);
    }
}
