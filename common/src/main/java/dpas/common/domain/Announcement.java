package dpas.common.domain;

import com.google.protobuf.ByteString;
import dpas.common.domain.constants.CryptographicConstants;
import dpas.common.domain.constants.JsonConstants;
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

    public static final int MAX_MESSAGE_SIZE = 255;

    private final byte[] signature;
    private final User user;
    private final String message;
    private final Set<Announcement> references; // Can be null
    private final AnnouncementBoard board;
    private final long seq;
    private final String identifier;
    private final Map<String, String> broadcastProofs;

    public Announcement(byte[] signature, User user, String message, Set<Announcement> references,
                        AnnouncementBoard board, long seq) throws CommonDomainException {
        this(signature, user, message, references, board, seq, new HashMap<>());
    }

    public Announcement(byte[] signature, User user, String message, Set<Announcement> references,
                        AnnouncementBoard board, long seq, Map<String, String> broadcastProofs) throws CommonDomainException {

        validateAnnouncement(signature, user, message, references, board, seq);
        this.message = message;
        this.signature = signature;
        this.user = user;
        this.references = references;
        this.board = board;
        this.seq = seq;
        this.identifier = generateIdentifier();
        this.broadcastProofs = broadcastProofs;
    }

    public Announcement(PrivateKey signatureKey, User user, String message, Set<Announcement> references,
                        AnnouncementBoard board, long seq) throws CommonDomainException {

        this(generateSignature(signatureKey, message, getReferenceStrings(references), board, seq),
                user, message, references, board, seq);
    }


    public String getMessage() {
        return this.message;
    }

    public byte[] getSignature() {
        return this.signature;
    }

    public Set<Announcement> getReferences() {
        return this.references;
    }

    public User getUser() {
        return this.user;
    }

    public String getIdentifier() {
        return this.identifier;
    }

    public AnnouncementBoard getBoard() {
        return this.board;
    }

    public long getSeq() {
        return this.seq;
    }

    public void addProof(String serverId, String proof) {
        this.broadcastProofs.put(serverId, proof);
    }

    public Contract.Announcement toContract() {

        var referenceStrings = getReferenceStrings(this.references);

        return Contract.Announcement.newBuilder()
                .setMessage(this.message)
                .addAllReferences(referenceStrings)
                .setPublicKey(ByteString.copyFrom(this.user.getPublicKey().getEncoded()))
                .setSignature(ByteString.copyFrom(this.signature))
                .setSeq(this.seq)
                .setIdentifier(this.identifier)
                .putAllReadyProof(this.broadcastProofs)
                .build();
    }

    public JsonObject toJson(String type) {
        var jsonBuilder = Json.createObjectBuilder();

        String pubKey = Base64.getEncoder().encodeToString(this.user.getPublicKey().getEncoded());
        String sign = Base64.getEncoder().encodeToString(this.signature);

        final var arrayBuilder = Json.createArrayBuilder();
        getReferenceStrings(this.references).forEach(arrayBuilder::add);

        var mapBuilder = Json.createObjectBuilder();
        for (Map.Entry<String, String> entry : this.broadcastProofs.entrySet()) {
            mapBuilder.add(entry.getKey(), entry.getValue());
        }

        jsonBuilder.add(JsonConstants.OPERATION_TYPE_KEY, type);
        jsonBuilder.add(JsonConstants.PUBLIC_KEY, pubKey);
        jsonBuilder.add(JsonConstants.MESSAGE_KEY, this.message);
        jsonBuilder.add(JsonConstants.SIGNATURE_KEY, sign);
        jsonBuilder.add(JsonConstants.SEQUENCER_KEY, this.seq);
        jsonBuilder.add(JsonConstants.REFERENCES_KEY, arrayBuilder.build());
        jsonBuilder.add(JsonConstants.BROADCAST_PROOF_KEY, mapBuilder);

        return jsonBuilder.build();
    }

    private String generateIdentifier() throws CommonDomainException {
        try {

            MessageDigest digest = MessageDigest.getInstance(CryptographicConstants.DIGEST_ALGORITHM);

            String identifier = this.seq + this.board.getIdentifier() +
                    Base64.getEncoder().encodeToString(this.user.getPublicKey().getEncoded());

            byte[] hash = digest.digest(identifier.getBytes());
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
            var sign = Signature.getInstance(CryptographicConstants.SIGNATURE_ALGORITHM);
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


    public static void validateAnnouncement(byte[] signature, User user, String message, Set<Announcement> references,
                                            AnnouncementBoard board, long seq) throws CommonDomainException {
        checkArguments(signature, user, message, references, board);
        checkSignature(signature, user, message, getReferenceStrings(references), board.getIdentifier(), seq);
    }

    public static void checkArguments(byte[] signature, User user, String message,
                                      Set<Announcement> references, AnnouncementBoard board) throws CommonDomainException {

        if (signature == null) {
            throw new NullSignatureException("Invalid Signature provided: null");
        }
        if (user == null) {
            throw new NullUserException("Invalid User provided: Does Not Exist");
        }
        if (message == null) {
            throw new NullMessageException("Invalid Message Provided: null");
        }
        if (message.length() > MAX_MESSAGE_SIZE) {
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

    public static void checkSignature(byte[] signature, User user, String message,
                                      Set<String> references, String boardIdentifier, long seq) throws CommonDomainException {
        try {

            byte[] messageBytes = generateMessageBytes(message, references, boardIdentifier, seq);
            PublicKey publicKey = user.getPublicKey();

            Signature sign = Signature.getInstance(CryptographicConstants.SIGNATURE_ALGORITHM);
            sign.initVerify(publicKey);
            sign.update(messageBytes);

            if (!sign.verify(signature))
                throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");

        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            throw new InvalidSignatureException("Invalid Signature: Invalid Security Values Provided");
        }
    }
}
