package dpas.common.domain;

import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.Assert.assertArrayEquals;

public class UserTest {

    private PublicKey _publicKey;

    @Before
    public void setup() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        _publicKey = keyPair.getPublic();
    }

    @After
    public void teardown() {

    }

    @Test
    public void validUser() throws NullPublicKeyException, NullUserException {
        User user = new User(_publicKey);
        assertArrayEquals(user.getPublicKey().getEncoded(), _publicKey.getEncoded());
    }

    @Test(expected = NullPublicKeyException.class)
    public void nullPublicKeyUser() throws NullPublicKeyException, NullUserException {
        new User(null);
    }

}
