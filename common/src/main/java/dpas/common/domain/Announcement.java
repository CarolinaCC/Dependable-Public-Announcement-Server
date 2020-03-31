package dpas.common.domain;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;

import javax.json.Json;
import javax.json.JsonObject;
import java.security.*;
import java.util.*;
import java.util.stream.Collectors;

public class Announcement {
    private byte[] _signature;
    private User _user;
    private String _message;
    private Set<Announcement> _references; // Can be null
    private int _sequencer;
    private String _hash;
    private AnnouncementBoard _board;

    public Announcement(byte[] signature, User user, String message, Set<Announcement> references,
                        int sequencer, AnnouncementBoard board) throws CommonDomainException {

        checkArguments(signature, user, message, sequencer, references, board);
        checkSignature(signature, user, message, getReferenceStrings(references), board.getIdentifier());
        _message = message;
        _signature = signature;
        _user = user;
        _references =  references;
        _sequencer = sequencer;
        _board = board;
        generateHash();
    }

    public Announcement(PrivateKey signatureKey, User user, String message, Set<Announcement> references,
                        int sequencer, AnnouncementBoard board) throws CommonDomainException {

        this(generateSignature(signatureKey, message, getReferenceStrings(references), board),
                user, message, references, sequencer, board);
    }


    public void checkArguments(byte[] signature, User user, String message, int identifier,
                               Set<Announcement> references, AnnouncementBoard board) throws CommonDomainException {

        if (signature == null) {
            throw new NullSignatureException("Invalid Signature provided: null");
        }
        if (user == null) {
            throw new NullUserException("Invalid User provided: null");
        }
        if (message == null) {
            throw new NullMessageException("Invalid Message Provided: null");
        }
        if (message.length() > 255) {
            throw new InvalidMessageSizeException("Invalid Message Length provided: over 255 characters");
        }
        if (board == null) {
            throw new InvalidBoardException("Invalid Board Provided: can't be null");
        }
        if (references != null) {
            if (references.contains(null)) {
                throw new NullAnnouncementException("Invalid Reference: A reference cannot be null");
            }
        }
    }

    public void checkSignature(byte[] signature, User user, String message,
                               Set<String> references, String boardIdentifier) throws CommonDomainException {
        try {

            byte[] messageBytes = generateMessageBytes(message, references, boardIdentifier);
            PublicKey publicKey = user.getPublicKey();

            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(messageBytes);

            if (!sign.verify(signature))
                throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");

        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");
        }
    }

    public String getMessage() {
        return _message;
    }

    public byte[] getSignature() {
        return _signature;
    }

    public Set<Announcement> getReferences() {
        return _references;
    }

    public User getUser() {
        return _user;
    }

    public int getSequencer() {
        return _sequencer;
    }

    public String getHash() {
        return _hash;
    }

    public AnnouncementBoard getBoard() {
        return _board;
    }

    private void generateHash() throws CommonDomainException {
        try {
            var builder = new StringBuilder();
            builder.append(_message)
                    .append(_sequencer)
                    .append(Base64.getEncoder().encodeToString(_signature))
                    .append(_board.getIdentifier())
                    .append(Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded()));
            getReferenceStrings(_references).forEach(builder::append);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(builder.toString().getBytes());
            _hash = Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            //Should never happen
            throw new InvalidHashException("Error: Could not get SHA-256 Hash");
        }

    }

    public Contract.Announcement toContract() {

        var references = getReferenceStrings(_references);

        return Contract.Announcement.newBuilder()
                .setMessage(_message)
                .addAllReferences(references)
                .setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
                .setSignature(ByteString.copyFrom(_signature))
                .setSequencer(_sequencer)
                .setHash(_hash)
                .build();
    }

    public JsonObject toJson(String type) {
        var jsonBuilder = Json.createObjectBuilder();

        String pubKey = Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded());
        String sign = Base64.getEncoder().encodeToString(_signature);

        final var arrayBuilder = Json.createArrayBuilder();
        getReferenceStrings(_references).forEach(arrayBuilder::add);

        jsonBuilder.add("Type", type);
        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("Message", _message);
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Sequencer", _sequencer);
        jsonBuilder.add("References", arrayBuilder.build());

        return jsonBuilder.build();
    }

    public static byte[] generateSignature(PrivateKey privKey, String message,
                                           Set<String> references, String boadIdentifier) throws CommonDomainException {
        try {
            var messageBytes = generateMessageBytes(message, references, boadIdentifier);
            var sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privKey);
            sign.update(messageBytes);
            return sign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new InvalidSignatureException("Invalid Signature: could not be created");
        }
    }


    public static byte[] generateSignature(PrivateKey privKey, String message,
                                           Set<String> references, AnnouncementBoard board) throws CommonDomainException {

        return generateSignature(privKey, message, references, board.getIdentifier());
    }

    public static Set<String> getReferenceStrings(Set<Announcement> references) {
        return references == null ? new HashSet<>()
                : references.stream().map(Announcement::getHash).collect(Collectors.toSet());
    }

    private static byte[] generateMessageBytes(String message, Set<String> references, String boardIdentifier) {
        var builder = new StringBuilder();
        builder.append(message);
        if (references != null) {
            references.forEach(builder::append);
        }
        builder.append(boardIdentifier);
        return builder.toString().getBytes();
    }
}
