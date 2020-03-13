package dpas.common.domain;

import static org.junit.Assert.assertEquals;
import dpas.common.domain.exception.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.*;

public class UserBoardTest {

    private Announcement _announcementA;
    private Announcement _announcementB;
    private User _userA;
    private User _userB;
    private UserBoard _userBoard;

    @Before
    public void setup() throws NullPublicKeyException, NullUsernameException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NullMessageException, UnsupportedEncodingException, NullSignatureException, NullUserException, InvalidMessageSizeException, NullAnnouncementException, InvalidSignatureException {
        // generate user A
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        _userA = new User("FIRST_USER_NAME", publicKey);
        //Generate valid signature
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update("MESSAGE".getBytes());
        byte[] signature = sign.sign();
        // Generate Announcement A
        _announcementA = new Announcement(signature, _userA, "MESSAGE", null);


        // generate user B
        keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        publicKey = keyPair.getPublic();
        _userB = new User("FIRST_USER_NAME", publicKey);
        //Generate valid signature
        sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update("MESSAGE".getBytes());
        signature = sign.sign();
        // Generate Announcement B
        _announcementB = new Announcement(signature, _userB, "MESSAGE", null);

        // Generate Board
        _userBoard = new UserBoard(_userA);
    }

    @After
    public void tearDown() {
    }






}
