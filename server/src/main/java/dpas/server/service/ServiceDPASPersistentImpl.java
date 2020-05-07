package dpas.server.service;

import dpas.common.domain.Announcement;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.server.persistence.PersistenceManager;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

import static dpas.common.domain.constants.CryptographicConstants.ASYMMETRIC_KEY_ALGORITHM;
import static dpas.common.domain.constants.JsonConstants.POST_GENERAL_OP_TYPE;
import static dpas.common.domain.constants.JsonConstants.POST_OP_TYPE;

public class ServiceDPASPersistentImpl extends ServiceDPASImpl {
    protected PersistenceManager manager;
    protected final Set<String> nonces = Collections.synchronizedSet(new HashSet<>());

    public ServiceDPASPersistentImpl(PersistenceManager manager) {
        super();
        this.manager = manager;
    }

    @Override
    public void register(RegisterRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM)
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = new User(key);

            User curr = users.putIfAbsent(key, user);
            if (curr != null) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                manager.save(user.toJson());
                responseObserver.onNext(MacReply.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Invalid Public Key").asRuntimeException());
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            // Should never happen
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        }
    }

    @Override
    public void post(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request);

            var curr = announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr != null) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                manager.save(announcement.toJson(POST_OP_TYPE));
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(MacReply.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            // Should never happen
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Key Provided").asRuntimeException());
        }

    }

    @Override
    public void postGeneral(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            Announcement announcement = generateAnnouncement(request, generalBoard);

            var curr = announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr != null) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                manager.save(announcement.toJson(POST_GENERAL_OP_TYPE));
                generalBoard.post(announcement);
                responseObserver.onNext(MacReply.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            // Should never happen
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Key Provided").asRuntimeException());
        }
    }

    public void addUser(PublicKey key) throws NullUserException, NullPublicKeyException {
        User user = new User(key);
        users.put(key, user);
    }


    public void addAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references, long seq, Map<String, String> broadcastProof)
            throws CommonDomainException {

        var refs = getReferences(references);
        var user = users.get(key);
        var board = user.getUserBoard();

        var announcement = new Announcement(signature, user, message, refs, board, seq, broadcastProof);
        board.post(announcement);
        announcements.put(announcement.getIdentifier(), announcement);
    }

    public void addGeneralAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references, long seq, Map<String, String> broadcastProof)
            throws CommonDomainException {

        var refs = getReferences(references);
        var user = users.get(key);
        var board = generalBoard;

        var announcement = new Announcement(signature, user, message, refs, board, seq, broadcastProof);
        generalBoard.post(announcement);
        announcements.put(announcement.getIdentifier(), announcement);
    }

    public ConcurrentHashMap<PublicKey, User> getUsers() {
        return this.users;
    }

    public ConcurrentHashMap<String, Announcement> getAnnouncements() {
        return this.announcements;
    }

    public void addNonce(String nonce) {
        nonces.add(nonce);
    }

    public boolean isReadRepeated(String nonce) {
        return nonces.contains(nonce);
    }

}
