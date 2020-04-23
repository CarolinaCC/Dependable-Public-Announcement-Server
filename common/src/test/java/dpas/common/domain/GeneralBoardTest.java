package dpas.common.domain;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidNumberOfPostsException;
import dpas.common.domain.exception.NullAnnouncementException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.*;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class GeneralBoardTest {

    private Announcement _announcement;
    private Announcement _announcement2;
    private Announcement _announcement3;
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

        // Generate Board
        _generalBoard = new GeneralBoard();

        byte[] signature = Announcement.generateSignature(privateKey, "MESSAGE", null, _generalBoard, _seq);

        byte[] signature2 = Announcement.generateSignature(privateKey, "MESSAGE", null, _generalBoard, _seq + 1);

        // Generate Announcement
        _announcement = new Announcement(signature, userA, "MESSAGE", null, _generalBoard, _seq);

        _announcement2 = new Announcement(signature2, userA, "MESSAGE", null, _generalBoard, _seq + 1);

        keyPair = keygen.generateKeyPair();
        privateKey = keyPair.getPrivate();
        publicKey = keyPair.getPublic();
        User userB = new User(publicKey);

        byte[] signature3 = Announcement.generateSignature(privateKey, "MESSAGE", null, _generalBoard, _seq + 1);

        _announcement3 = new Announcement(signature3, userB, "MESSAGE", null, _generalBoard, _seq + 1);
    }

    @After
    public void tearDown() {
    }

    @Test
    public void validPost() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        assertEquals(_generalBoard.read(1).get(0), _announcement);
    }

    @Test
    public void sameSeqDifferentKeyPost() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement2);
        _generalBoard.post(_announcement);
        _generalBoard.post(_announcement3);
        assertTrue(_generalBoard.read(0).contains(_announcement));
        assertTrue(_generalBoard.read(0).contains(_announcement3));
        assertTrue(_generalBoard.read(0).contains(_announcement2));
        assertEquals(_generalBoard.read(0).size(), 3);
        assertEquals(_generalBoard.getSeq(), _seq + 1);
    }


    @Test
    public void repeatedPost() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        _generalBoard.post(_announcement);
        assertEquals(_generalBoard.read(2).get(0), _announcement);
        assertEquals(_generalBoard.read(2).size(), 1);
        assertEquals(_generalBoard.getSeq(), _seq);
    }

    @Test
    public void emptyMaxSeq() {
        assertEquals(_generalBoard.getSeq(), 0);
    }

    @Test(expected = NullAnnouncementException.class)
    public void nullAnnouncementPost() throws NullAnnouncementException {
        _generalBoard.post(null);
    }

    @Test
    public void validRead() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        _generalBoard.post(_announcement2);
        ArrayList<Announcement> expectedAnnouncements = new ArrayList<Announcement>();
        expectedAnnouncements.add(_announcement);
        expectedAnnouncements.add(_announcement2);
        assertEquals(_generalBoard.read(2), expectedAnnouncements);
    }

    @Test
    public void validReadSubset() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        _generalBoard.post(_announcement2);
        assertEquals(_generalBoard.read(1).get(0), _announcement2);
    }

    @Test(expected = InvalidNumberOfPostsException.class)
    public void invalidNumberOfPostsRead() throws NullAnnouncementException, InvalidNumberOfPostsException {
        _generalBoard.post(_announcement);
        _generalBoard.read(-1);
    }

}