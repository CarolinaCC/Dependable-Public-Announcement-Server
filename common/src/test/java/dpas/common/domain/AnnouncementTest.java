package dpas.common.domain;

import dpas.common.domain.exception.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class AnnouncementTest {

    private static final String MESSAGE = "Hello World";
    private static final String OTHER_MESSAGE = "This is another announcement";
    private static final byte[] MESSAGE_BYTES = MESSAGE.getBytes();
    private static final String INVALID_MESSAGE = "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid" +
            "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid";

    private ArrayList<Announcement> _references = new ArrayList<>();
    private byte[] _signature;
    private String _identifier;
    
    private User _user;
    
    private PublicKey _pubKey;
    private PrivateKey _privKey;

    @Before
    public void setup() throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, UnsupportedEncodingException, CommonDomainException {

        //Generate public key
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048);
        KeyPair keyPair = keygen.generateKeyPair();
        _privKey = keyPair.getPrivate();
        _pubKey = keyPair.getPublic();

        //Generate user
        this._user = new User(_pubKey);

        _identifier = UUID.randomUUID().toString();
        this._signature = Announcement.generateSignature(_privKey, MESSAGE, _identifier, new ArrayList<String>(), _pubKey);



        //Create another announcement
        KeyPairGenerator otherKeyGen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048);
        KeyPair otherKeyPair = otherKeyGen.generateKeyPair();
        PublicKey otherPublicKey = otherKeyPair.getPublic();
        PrivateKey otherPrivateKey = otherKeyPair.getPrivate();

        byte[] otherSignature = Announcement.generateSignature(otherPrivateKey, OTHER_MESSAGE, _identifier, new ArrayList<String>(), _pubKey);
        	
        User otherUser = new User(otherPublicKey);
        Announcement ref = new Announcement(otherSignature, otherUser, OTHER_MESSAGE, null, _identifier, _pubKey);

        //Add it to references
        _references.add(ref);
    }

    @After
    public void tearDown() {

    }

    @Test
    public void validAnnouncement() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {
    	List<String> refs = _references.stream().map(Announcement::getIdentifier).collect(Collectors.toList());
    	byte[] signature = Announcement.generateSignature(_privKey, MESSAGE, _identifier, refs, _pubKey);
    	
        Announcement announcement = new Announcement(signature, _user, MESSAGE, _references, _identifier, _pubKey);
        assertEquals(announcement.getSignature(), signature);
        assertEquals(announcement.getUser(), _user);
        assertEquals(announcement.getMessage(), MESSAGE);
        assertEquals(announcement.getReferences(), _references);
    }

    @Test
    public void validAnnouncementNullReference() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {

        Announcement announcement = new Announcement(_signature, _user, MESSAGE, null, _identifier, _pubKey);
        assertEquals(announcement.getSignature(), _signature);
        assertEquals(announcement.getUser(), _user);
        assertEquals(announcement.getMessage(), MESSAGE);
        assertNull(announcement.getReferences());
    }

    @Test(expected = NullSignatureException.class)
    public void nullSignature() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {

        new Announcement(null, _user, MESSAGE, _references, _identifier, _pubKey);
    }


    @Test(expected = NullUserException.class)
    public void nullUser() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {

        new Announcement(_signature, null, MESSAGE, _references, _identifier, _pubKey);
    }

    @Test(expected = NullMessageException.class)
    public void nullMessage() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {

    	new Announcement(_signature, _user, null, _references, _identifier, _pubKey);
    }

    @Test(expected = NullAnnouncementException.class)
    public void nullReferences() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {

        ArrayList<Announcement> refNullElement = new ArrayList<>();
        refNullElement.add(null);

        new Announcement(_signature, _user, MESSAGE, refNullElement, _identifier, _pubKey);
    }

    @Test(expected = InvalidSignatureException.class)
    public void invalidSignature() throws InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, UnsupportedEncodingException, CommonDomainException {

        byte[] invalidSig = "InvalidSignature".getBytes();
        new Announcement(invalidSig, _user, MESSAGE, _references, _identifier, _pubKey);
    }

    @Test(expected = InvalidMessageSizeException.class)
    public void invalidMessage() throws InvalidKeyException, NoSuchAlgorithmException, UnsupportedEncodingException,
            SignatureException, CommonDomainException {

        new Announcement(_signature, _user, INVALID_MESSAGE, _references, _identifier, _pubKey);
    }


}
