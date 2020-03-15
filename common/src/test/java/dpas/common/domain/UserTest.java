package dpas.common.domain;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;


import javax.crypto.KeyGenerator;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class UserTest {


    private static final String FIRST_USER_NAME = "FIRST_USER_NAME";
    private static final String SECOND_USER_NAME = "SECOND_USER_NAME";


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
        User user = new User(FIRST_USER_NAME, _publicKey);
        assertEquals(user.getUsername(), FIRST_USER_NAME);
        assertArrayEquals(user.getPublicKey().getEncoded(), _publicKey.getEncoded());
    }

    @Test(expected = NullPublicKeyException.class)
    public void nullPublicKeyUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        User user = new User(FIRST_USER_NAME, null);
    }

    @Test(expected = NullUsernameException.class)
    public void nullUsernameUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        User user = new User(null, _publicKey);
    }

    @Test(expected = NullUsernameException.class)
    public void emptyUsernameUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        User user = new User("", _publicKey);
    }

    @Test(expected = NullUsernameException.class)
    public void tabUsernameUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        User user = new User("\t", _publicKey);
    }

    @Test(expected = NullUsernameException.class)
    public void newlineUsernameUser() throws NullPublicKeyException, NullUsernameException, NullUserException {
        User user = new User("\n", _publicKey);
    }
}
