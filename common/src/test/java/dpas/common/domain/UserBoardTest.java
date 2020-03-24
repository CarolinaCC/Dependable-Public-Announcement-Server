package dpas.common.domain;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class UserBoardTest {

    private Announcement _announcementValid;
    private Announcement _announcementValid2;
    private Announcement _announcementInvalid;
    private UserBoard _userBoard;

    private String _identifier;
    private String _identifier2;
    private String _identifierInvalid;

    private static final String FIRST_MESSAGE = "Message";
    private static final String SECOND_MESSAGE = "Second Message";

    @Before
    public void setup() throws CommonDomainException, NoSuchAlgorithmException {
        // generate user A

        _identifier = UUID.randomUUID().toString();
        _identifier2 = UUID.randomUUID().toString();
        _identifierInvalid = UUID.randomUUID().toString();

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        User user = new User(publicKey);

        _userBoard = user.getUserBoard();

        byte[] signature = Announcement.generateSignature(keyPair.getPrivate(), FIRST_MESSAGE, null, _userBoard);

        // Generate Announcement A
        _announcementValid = new Announcement(signature, user, FIRST_MESSAGE, null, _identifier, _userBoard);

        //Generate References
        ArrayList<Announcement> references = new ArrayList<>(Collections.singletonList(_announcementValid));
        List<String> referenceIds = Announcement.getReferenceStrings(references);

        //Generate valid signature for second message
        byte[] signature2 = Announcement.generateSignature(keyPair.getPrivate(), SECOND_MESSAGE, referenceIds, _userBoard);

        _announcementValid2 = new Announcement(signature2, user, SECOND_MESSAGE, references, _identifier2, _userBoard);

        // Get UserBoard
        _userBoard = user.getUserBoard();

        // generate user B
        keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        publicKey = keyPair.getPublic();
        user = new User(publicKey);

        byte[] signatureInvalid = Announcement.generateSignature(keyPair.getPrivate(), FIRST_MESSAGE, null, _userBoard);

        // Generate Announcement B
        _announcementInvalid = new Announcement(signatureInvalid, user, FIRST_MESSAGE, null, _identifierInvalid, _userBoard);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void validPost() throws InvalidNumberOfPostsException, InvalidUserException, NullAnnouncementException {
        _userBoard.post(_announcementValid);
        ArrayList<Announcement> announcements = _userBoard.read(1);
        assertEquals(announcements.get(0), _announcementValid);
    }


    @Test(expected = NullAnnouncementException.class)
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
        _userBoard.post(_announcementValid2);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcementValid);
        expectedAnnouncements.add(_announcementValid2);
        assertEquals(_userBoard.read(2), expectedAnnouncements);
    }

    @Test
    public void valueZeroRead() throws NullAnnouncementException, InvalidNumberOfPostsException, InvalidUserException {
        _userBoard.post(_announcementValid);
        _userBoard.post(_announcementValid2);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcementValid);
        expectedAnnouncements.add(_announcementValid2);
        assertEquals(_userBoard.read(0), expectedAnnouncements);
    }

    @Test
    public void valueHigherThanPostsRead() throws NullAnnouncementException, InvalidNumberOfPostsException, InvalidUserException {
        _userBoard.post(_announcementValid);
        _userBoard.post(_announcementValid2);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcementValid);
        expectedAnnouncements.add(_announcementValid2);
        assertEquals(_userBoard.read(7), expectedAnnouncements);
    }

    @Test
    public void readSubsetOfPosts() throws NullAnnouncementException, InvalidNumberOfPostsException, InvalidUserException {
        _userBoard.post(_announcementValid);
        _userBoard.post(_announcementValid2);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcementValid2);
        assertEquals(_userBoard.read(1), expectedAnnouncements);
    }

    @Test(expected = InvalidNumberOfPostsException.class)
    public void invalidNumberOfPostsRead() throws NullAnnouncementException, InvalidNumberOfPostsException, InvalidUserException {
        _userBoard.post(_announcementValid);
        _userBoard.read(-1);
    }
}
