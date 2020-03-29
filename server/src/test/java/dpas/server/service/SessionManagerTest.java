package dpas.server.service;

import dpas.server.session.Session;
import dpas.server.session.SessionManager;
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
    @Before
    public void setup() throws NoSuchAlgorithmException {
        _manager = new SessionManager();

    }

    @Test
    public void cleanupTest() throws NoSuchAlgorithmException {
        KeyPairGenerator keyFactory = KeyPairGenerator.getInstance("RSA");
        KeyPair keyPair = keyFactory.generateKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privKey = keyPair.getPrivate();
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
}
