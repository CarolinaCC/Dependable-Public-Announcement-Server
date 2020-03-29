package dpas.server.service;

import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import io.grpc.StatusRuntimeException;
import org.junit.Before;
import org.junit.Test;

import java.security.*;
import java.time.LocalDateTime;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SessionManagerTest {

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
        KeyPair keyPair2 = keygen.generateKeyPair();

        _pubKey = keyPair.getPublic();

    }

    @Test
    public void cleanupTest() throws NoSuchAlgorithmException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime =  LocalDateTime.now().plusHours(1);
        Session validSession = new Session(0, pubKey, SESSION_NONCE, validTime);
        Session invalidSession = new Session(0, pubKey, SESSION_NONCE2, LocalDateTime.now().minusHours(1));
        _manager.getSessionKeys().put(SESSION_NONCE, validSession);
        _manager.getSessionKeys().put(SESSION_NONCE2, invalidSession);
        _manager.cleanup();
        assertEquals(_manager.getSessionKeys().size(), 1);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_sequenceNumber(), 0);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_sessionNonce(), SESSION_NONCE);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_publicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_validity(), validTime);
    }

    @Test
    public void multipleSessionsCleanupTest() throws NoSuchAlgorithmException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        LocalDateTime validTime =  LocalDateTime.now().plusHours(1);

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
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_sequenceNumber(), 0);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_sessionNonce(), SESSION_NONCE);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_publicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_validity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE2).get_sequenceNumber(), 1);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE2).get_sessionNonce(), SESSION_NONCE2);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE2).get_publicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE2).get_validity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE3).get_sequenceNumber(), 2);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE3).get_sessionNonce(), SESSION_NONCE3);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE3).get_publicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE3).get_validity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE4).get_sequenceNumber(), 3);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE4).get_sessionNonce(), SESSION_NONCE4);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE4).get_publicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE4).get_validity(), validTime);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE5).get_sequenceNumber(), 4);
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE5).get_sessionNonce(), SESSION_NONCE5);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE5).get_publicKey().getEncoded(), pubKey.getEncoded());
        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE5).get_validity(), validTime);

    }

    @Test
    public void createSessionValid() {

        SessionManager manager = new SessionManager(5);
        manager.createSession( _pubKey, SESSION_NONCE);

        assertEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_sessionNonce(), SESSION_NONCE);
        assertArrayEquals(_manager.getSessionKeys().get(SESSION_NONCE).get_publicKey().getEncoded(), _pubKey.getEncoded());
    }

    @Test (expected = IllegalArgumentException.class)
    public void createSameSessionNonce() {

        SessionManager manager = new SessionManager(5);
        manager.createSession(_pubKey, SESSION_NONCE);
        manager.createSession( _pubKey, SESSION_NONCE);
    }

}
