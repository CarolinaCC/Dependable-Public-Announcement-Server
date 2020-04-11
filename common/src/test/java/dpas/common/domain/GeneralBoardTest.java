package dpas.common.domain;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.NullAnnouncementException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.*;
import java.util.ArrayList;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class GeneralBoardTest {

    private Announcement _announcement;
    private GeneralBoard _generalBoard;
    private long _seq;

    @Before
    public void setup() throws CommonDomainException, NoSuchAlgorithmException {
        // generate user
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();
        User userA = new User(publicKey);

        _seq = 1;

        UUID.randomUUID().toString();

        // Generate Board
        _generalBoard = new GeneralBoard();

        byte[] signature = Announcement.generateSignature(privateKey, "MESSAGE", null, _generalBoard, _seq);

        // Generate Announcement
        _announcement = new Announcement(signature, userA, "MESSAGE", null, _generalBoard, _seq);

    }

    @After
    public void tearDown() {
    }

    @Test
    public void validPost() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        assertEquals(_generalBoard.read(1).get(0), _announcement);
    }

    @Test(expected = NullAnnouncementException.class)
    public void nullAnnouncementPost() throws NullAnnouncementException {
        _generalBoard.post(null);
    }

    @Test
    public void validRead() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        _generalBoard.post(_announcement);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcement);
        expectedAnnouncements.add(_announcement);
        assertEquals(_generalBoard.read(2), expectedAnnouncements);
    }

    @Test(expected = InvalidNumberOfPostsException.class)
    public void invalidNumberOfPostsRead() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        _generalBoard.read(-1);
    }

}