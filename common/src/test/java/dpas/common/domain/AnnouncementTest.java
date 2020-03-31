package dpas.common.domain;

import dpas.common.domain.exception.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class AnnouncementTest {

    private static final String MESSAGE = "Hello World";
    private static final String OTHER_MESSAGE = "This is another announcement";
    private static final String INVALID_MESSAGE = "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid" +
            "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid";

    private Set<Announcement> _references = new HashSet<>();
    private byte[] _signature;

    private User _user;

    private PrivateKey _privKey;

    private AnnouncementBoard _board;


    @Before
    public void setup() throws NoSuchAlgorithmException, CommonDomainException {

        //Generate public key
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048);
        KeyPair keyPair = keygen.generateKeyPair();
        _privKey = keyPair.getPrivate();
        PublicKey _pubKey = keyPair.getPublic();

        //Generate user
        this._user = new User(_pubKey);
        this._board = new UserBoard(_user);

        this._signature = Announcement.generateSignature(_privKey, MESSAGE, new HashSet<>(), _board);


        //Create another announcement
        KeyPairGenerator otherKeyGen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048);
        KeyPair otherKeyPair = otherKeyGen.generateKeyPair();
        PublicKey otherPublicKey = otherKeyPair.getPublic();
        PrivateKey otherPrivateKey = otherKeyPair.getPrivate();

        byte[] otherSignature = Announcement.generateSignature(otherPrivateKey, OTHER_MESSAGE, new HashSet<>(), _board);

        User otherUser = new User(otherPublicKey);
        Announcement ref = new Announcement(otherSignature, otherUser, OTHER_MESSAGE, null, 0, _board);

        //Add it to references
        _references.add(ref);
    }

    @After
    public void tearDown() {

    }

    @Test
    public void validAnnouncement() throws CommonDomainException {
        var refs = _references.stream().map(Announcement::getHash).collect(Collectors.toSet());
        byte[] signature = Announcement.generateSignature(_privKey, MESSAGE, refs, _board);

        Announcement announcement = new Announcement(signature, _user, MESSAGE, _references, 0, _board);
        assertEquals(announcement.getSignature(), signature);
        assertEquals(announcement.getUser(), _user);
        assertEquals(announcement.getMessage(), MESSAGE);
        assertEquals(announcement.getReferences(), _references);
    }

    @Test
    public void validAnnouncementNullReference() throws CommonDomainException {
        Announcement announcement = new Announcement(_signature, _user, MESSAGE, null, 0, _board);
        assertEquals(announcement.getSignature(), _signature);
        assertEquals(announcement.getUser(), _user);
        assertEquals(announcement.getMessage(), MESSAGE);
        assertNull(announcement.getReferences());
    }

    @Test(expected = NullSignatureException.class)
    public void nullSignature() throws CommonDomainException {
        new Announcement((byte[]) null, _user, MESSAGE, _references, 0, _board);
    }


    @Test(expected = NullUserException.class)
    public void nullUser() throws CommonDomainException {
        new Announcement(_signature, null, MESSAGE, _references, 0, _board);
    }

    @Test(expected = NullMessageException.class)
    public void nullMessage() throws CommonDomainException {
        new Announcement(_signature, _user, null, _references, 0, _board);
    }

    @Test(expected = NullAnnouncementException.class)
    public void nullReferences() throws CommonDomainException {
        var refs = new HashSet<Announcement>();
        refs.add(null);

        new Announcement(_signature, _user, MESSAGE, refs, 0, _board);
    }

    @Test(expected = InvalidSignatureException.class)
    public void invalidSignature() throws CommonDomainException {
        byte[] invalidSig = "InvalidSignature".getBytes();
        new Announcement(invalidSig, _user, MESSAGE, _references, 0, _board);
    }

    @Test(expected = InvalidSignatureException.class)
    public void wrongSignature() throws CommonDomainException {
        new Announcement(_signature, _user, OTHER_MESSAGE, _references, 0, _board);
    }

    @Test(expected = InvalidMessageSizeException.class)
    public void invalidMessage() throws CommonDomainException {
        new Announcement(_signature, _user, INVALID_MESSAGE, _references, 0, _board);
    }


}
