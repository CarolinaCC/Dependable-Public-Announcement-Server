package dpas.common.domain;

import static org.junit.Assert.assertEquals;

import dpas.common.domain.exception.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.ArrayList;

public class UserBoardTest {

    private Announcement _announcementValid;
    private Announcement _announcementInvalid;
    private UserBoard _userBoard;

    @Before
    public void setup() throws NullPublicKeyException, NullUsernameException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NullMessageException, UnsupportedEncodingException, NullSignatureException, NullUserException, InvalidMessageSizeException, NullAnnouncementException, InvalidSignatureException {
        // generate user A
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        User user = new User("FIRST_USER_NAME", publicKey);
        //Generate valid signature
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update("MESSAGE".getBytes());
        byte[] signature = sign.sign();
        // Generate Announcement A
        _announcementValid = new Announcement(signature, user, "MESSAGE", null);

        // Get UserBoard
        _userBoard = user.getUserBoard();

        // generate user B
        keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        publicKey = keyPair.getPublic();
        user = new User("FIRST_USER_NAME", publicKey);
        //Generate valid signature
        sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update("MESSAGE".getBytes());
        signature = sign.sign();
        // Generate Announcement B
        _announcementInvalid = new Announcement(signature, user, "MESSAGE", null);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void validPost() throws InvalidNumberOfPostsException, InvalidUserException, NullAnnouncementException {
        _userBoard.post(_announcementValid);
        assertEquals(_userBoard.read(1).get(0), _announcementValid);
    }


    @Test(expected = NullUserException.class)
    public void nullAnnouncementPost() throws InvalidUserException, NullAnnouncementException {
        _userBoard.post(null);
    }

    @Test(expected = InvalidUserException.class)
    public void invalidUserPost() throws InvalidUserException, NullAnnouncementException {
        _userBoard.post(_announcementInvalid);
    }

    @Test
    public void validRead() throws NullAnnouncementException, InvalidNumberOfPostsException, InvalidUserException {
        _userBoard.post(_announcementValid);
        _userBoard.post(_announcementValid);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcementValid);
        expectedAnnouncements.add(_announcementValid);
        assertEquals(_userBoard.read(2), expectedAnnouncements);
    }

    @Test(expected = InvalidNumberOfPostsException.class)
    public void invalidNumberOfPostsRead() throws NullAnnouncementException, InvalidNumberOfPostsException, InvalidUserException {
        _userBoard.post(_announcementValid);
        _userBoard.read(-1);
    }


}
