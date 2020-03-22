package dpas.common.domain;

import static org.junit.Assert.assertArrayEquals;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;

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
    public void validUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        User user = new User(_publicKey);
        assertArrayEquals(user.getPublicKey().getEncoded(), _publicKey.getEncoded());
    }

    @Test(expected = NullPublicKeyException.class)
    public void nullPublicKeyUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        new User(null);
    }

}
