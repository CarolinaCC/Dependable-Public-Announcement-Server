package dpas.common.domain;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;

import javax.json.Json;
import javax.json.JsonObject;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class Announcement {
    private final byte[] _signature;
    private final User _user;
    private final String _message;
    private final Set<Announcement> _references; // Can be null
    private final AnnouncementBoard _board;
    private final long _seq;
    private final String _hash;
    private final String _identifier;
    private final Map<String, String> _broadcastProof;

    public Announcement(byte[] signature, User user, String message, Set<Announcement> references,
                        AnnouncementBoard board, long seq) throws CommonDomainException {

        checkArguments(signature, user, message, references, board, seq);
        checkSignature(signature, user, message, getReferenceStrings(references), board.getIdentifier(), seq);
        _message = message;
        _signature = signature;
        _user = user;
        _references = references;
        _board = board;
        _seq = seq;
        _hash = generateHash();
        _identifier = generateIdentifier();
        _broadcastProof = new HashMap<>();
    }

    public Announcement(byte[] signature, User user, String message, Set<Announcement> references,
                        AnnouncementBoard board, long seq, Map<String, String> broadcast) throws CommonDomainException {

        checkArguments(signature, user, message, references, board, seq);
        checkSignature(signature, user, message, getReferenceStrings(references), board.getIdentifier(), seq);
        _message = message;
        _signature = signature;
        _user = user;
        _references = references;
        _board = board;
        _seq = seq;
        _hash = generateHash();
        _identifier = generateIdentifier();
        _broadcastProof = broadcast;
    }

    public Announcement(PrivateKey signatureKey, User user, String message, Set<Announcement> references,
                        AnnouncementBoard board, long seq) throws CommonDomainException {

        this(generateSignature(signatureKey, message, getReferenceStrings(references), board, seq),
                user, message, references, board, seq);
    }


    public void checkArguments(byte[] signature, User user, String message,
                               Set<Announcement> references, AnnouncementBoard board, long seq) throws CommonDomainException {

        if (signature == null) {
            throw new NullSignatureException("Invalid Signature provided: null");
        }
        if (user == null) {
            throw new NullUserException("Invalid User provided: Does Not Exist");
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
                               Set<String> references, String boardIdentifier, long seq) throws CommonDomainException {
        try {

            byte[] messageBytes = generateMessageBytes(message, references, boardIdentifier, seq);
            PublicKey publicKey = user.getPublicKey();

            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(publicKey);
            sign.update(messageBytes);

            if (!sign.verify(signature))
                throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");

        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new InvalidSignatureException("Invalid Signature: Invalid Security Values Provided");
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

    public String getIdentifier() {
        return _identifier;
    }

    public AnnouncementBoard getBoard() {
        return _board;
    }

    public long getSeq() {
        return _seq;
    }

    public void addProof(String serverId, String sign) {
        _broadcastProof.put(serverId, sign);
    }

    public Contract.Announcement toContract() {

        var references = getReferenceStrings(_references);

        return Contract.Announcement.newBuilder()
                .setMessage(_message)
                .addAllReferences(references)
                .setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
                .setSignature(ByteString.copyFrom(_signature))
                .setSeq(_seq)
                .setIdentifier(_identifier)
                .putAllReadyProof(_broadcastProof)
                .build();
    }

    public JsonObject toJson(String type) {
        var jsonBuilder = Json.createObjectBuilder();

        String pubKey = Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded());
        String sign = Base64.getEncoder().encodeToString(_signature);

        final var arrayBuilder = Json.createArrayBuilder();
        getReferenceStrings(_references).forEach(arrayBuilder::add);

        var mapBuilder = Json.createObjectBuilder();
        for (Map.Entry<String, String> entry : _broadcastProof.entrySet()) {
            mapBuilder.add(entry.getKey(), entry.getValue());
        }

        //final var mapBuilder = Json.createArrayBuilder()
        jsonBuilder.add("Type", type);
        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("Message", _message);
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Sequencer", _seq);
        jsonBuilder.add("References", arrayBuilder.build());
        jsonBuilder.add("BroadCastProof", mapBuilder);

        return jsonBuilder.build();
    }

    private String generateHash() throws CommonDomainException {
        try {
            var builder = new StringBuilder();
            builder.append(_message)
                    .append(_seq)
                    .append(Base64.getEncoder().encodeToString(_signature))
                    .append(_board.getIdentifier())
                    .append(Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded()));
            getReferenceStrings(_references).forEach(builder::append);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(builder.toString().getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            //Should never happen
            throw new InvalidHashException("Error: Could not get SHA-256 Hash");
        }
    }

    private String generateIdentifier() throws CommonDomainException {
        try {
            var builder = new StringBuilder()
                    .append(_seq)
                    .append(_board.getIdentifier())
                    .append(Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded()));

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(builder.toString().getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (NoSuchAlgorithmException e) {
            //Should never happen
            throw new InvalidHashException("Error: Could not get SHA-256 Hash");
        }
    }


    public static byte[] generateSignature(PrivateKey privKey, String message,
                                           Set<String> references, String boadIdentifier, long seq) throws CommonDomainException {
        try {
            var messageBytes = generateMessageBytes(message, references, boadIdentifier, seq);
            var sign = Signature.getInstance("SHA256withRSA");
            sign.initSign(privKey);
            sign.update(messageBytes);
            return sign.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new InvalidSignatureException("Invalid Signature: could not be created");
        }
    }

    public static byte[] generateSignature(PrivateKey privKey, String message,
                                           Set<String> references, AnnouncementBoard board, long seq) throws CommonDomainException {
        return generateSignature(privKey, message, references, board.getIdentifier(), seq);
    }

    public static Set<String> getReferenceStrings(Set<Announcement> references) {
        return Stream.ofNullable(references)
                .flatMap(Set::stream)
                .map(Announcement::getIdentifier)
                .collect(Collectors.toSet());
    }

    public static byte[] generateMessageBytes(String message, Set<String> references, String boardIdentifier, long seq) {
        var builder = new StringBuilder();
        builder.append(message);
        Stream.ofNullable(references)
                .flatMap(Set::stream)
                .sorted() //Sort references to ensure the same signature on client and server
                .forEach(builder::append);
        builder.append(boardIdentifier);
        builder.append(seq);
        return builder.toString().getBytes();
    }
}
