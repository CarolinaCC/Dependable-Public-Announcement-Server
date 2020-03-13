package dpas.common.domain;

import dpas.common.domain.exception.*;

import java.security.*;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Date;

public class Announcement {
    private byte[] _signature;
    private User _user;
    private String _message;
    private ArrayList<Announcement> _references; // Can be null
    private LocalDate _publishTime; // Date and time of the post

    public Announcement(byte[] signature, User user, String message, ArrayList<Announcement> references, LocalDate publishTime) throws NullSignatureException, NullMessageException,
            NullPublishTimeException, NullPostException, InvalidSignatureException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NullUserException {

        checkArguments(signature, user, message, publishTime, references);
        checkSignature(signature, user, message);
        this._message = message;
        this._signature = signature;
        this._user = user;
        this._references = references;
        this._publishTime = publishTime;
    }

    public void checkArguments(byte[] signature, User user, String message, LocalDate publishTime, ArrayList<Announcement> references) throws NullSignatureException,
            NullMessageException, NullPublishTimeException, NullPostException, NullUserException {

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

        if (references != null) {
            if (references.contains(null)) {
                throw new NullPostException();
            }
        }
    }

    public void checkSignature(byte[] signature, User user, String message) throws InvalidSignatureException, InvalidKeyException, NoSuchAlgorithmException,
            SignatureException, NullMessageException {

        byte[] messageBytes = message.getBytes();
        PublicKey publicKey = user.getPublicKey();

        Signature sign = Signature.getInstance("SHA256withRSA"); // Hardcoded for now
        sign.initVerify(publicKey);
        sign.update(messageBytes);

        try {
            sign.verify(signature);
        } catch (SignatureException e) {
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

    public LocalDate getPublishTime() { return this._publishTime; }

    //public String printPublishTime() { return this._publishTime.toString(); }

    public User getUser() { return this._user; }

    public String getPostUsername() {
        return this._user.getUsername();
    }

}
