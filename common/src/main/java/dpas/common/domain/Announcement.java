package dpas.common.domain;

import dpas.common.domain.exception.*;

import java.security.*;
import java.util.ArrayList;
import java.util.Date;

public class Announcement {
    //FIXME: This could be a Signature, we will sign the message, so that is what should be passed to verify (converted to Byte[])
    private byte[] _signature;
    private User _user;
    private String _message;
    private ArrayList<Announcement> _references; // Can be null
    //FIXME not sure if this will be useful
    private Date _publishTime; // Date and time of the post

    public Announcement(byte[] signature, User user, String message, ArrayList<Announcement> references, Date publishTime) throws NullSignatureException, NullMessageException,
            NullPublishTimeException, NullPublicKeyException, NullPostException, InvalidSignatureException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NullUserException {

        checkArguments(signature, user, message, publishTime, references);
        checkSignature(signature, user);
        this._signature = signature;
        this._user = user;
        this._message = message;
        this._references = references;
        this._publishTime = publishTime;
    }

    public void checkArguments(byte[] signature, User user, String message, Date publishTime, ArrayList<Announcement> references) throws NullSignatureException,
            NullMessageException, NullPublishTimeException, NullPublicKeyException, NullPostException, NullUserException {

        if (signature == null) {
            throw new NullSignatureException();
        }
        if (user == null) {
            throw new NullUserException();
        }
        if (message == null) {
            throw new NullMessageException();
        }
        if (publishTime == null) {
            throw new NullPublishTimeException();
        }
        if (references.contains(null)) {
            throw new NullPostException();
        }
    }

    public void checkSignature(byte[] signature, User user) throws InvalidSignatureException, InvalidKeyException, NoSuchAlgorithmException,
            SignatureException {

        byte[] messageBytes = this._message.getBytes();

        //FIXME shouldn't we verify the signature with the User's public key?
        //Generate correct signature of the message
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair pair = keyPairGen.generateKeyPair();
        PrivateKey privateKey = pair.getPrivate();
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateKey);
        sign.update(messageBytes);

        //Check if both signatures match
        PublicKey publicKey = user.getPublicKey();
        sign.initVerify(publicKey);
        sign.update(messageBytes);

        if (!sign.verify(signature)) {
            throw new InvalidSignatureException();
        }
    }

    public String getMessage() {
        return this._message;
    }

    public byte[] getSignature() {
        return this._signature;
    }

    public ArrayList<Announcement> getReferences() {
        return this._references;
    }

    //public Date getPublishTime() { return this._publishTime; }
    public String printPublishTime() {
        return this._publishTime.toString();
    }

    public String getPostUser() {
        return this._user.getUsername();
    }

}
