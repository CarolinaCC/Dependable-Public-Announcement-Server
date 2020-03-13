package dpas.common.domain;

import dpas.common.domain.exception.*;

import java.security.*;
import java.util.ArrayList;

public class Announcement {
    private byte[] _signature;
    private User _user;
    private String _message;
    private ArrayList<Announcement> _references; // Can be null
    private int _sequenceNumber;

    public Announcement(byte[] signature, User user, String message, ArrayList<Announcement> references) throws NullSignatureException, NullMessageException,
            NullPostException, InvalidSignatureException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            NullUserException {

        checkArguments(signature, user, message, references);
        checkSignature(signature, user, message);
        this._message = message;
        this._signature = signature;
        this._user = user;
        this._references = references;
    }

    public void checkArguments(byte[] signature, User user, String message, ArrayList<Announcement> references) throws NullSignatureException,
            NullMessageException, NullPostException, NullUserException {

        if (signature == null) {
            throw new NullSignatureException();
        }
        if (user == null) {
            throw new NullUserException();
        }
        if (message == null) {
            throw new NullMessageException();
        }

        if (references != null) {
            if (references.contains(null)) {
                throw new NullPostException();
            }
        }
    }

    public void checkSignature(byte[] signature, User user, String message) throws InvalidSignatureException, InvalidKeyException, NoSuchAlgorithmException,
            SignatureException {

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

    public User getUser() {
        return this._user;
    }

    public String getPostUsername() {
        return this._user.getUsername();
    }

    public int get_sequenceNumber() {
        return _sequenceNumber;
    }

    public void set_sequenceNumber(int _sequenceNumber) {
        this._sequenceNumber = _sequenceNumber;
    }
}
