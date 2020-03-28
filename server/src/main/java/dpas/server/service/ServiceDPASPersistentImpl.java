package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class ServiceDPASPersistentImpl extends ServiceDPASImpl {
    private PersistenceManager _manager;

    public ServiceDPASPersistentImpl(PersistenceManager manager, PublicKey pubKey) {
        super();
        _manager = manager;
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<Empty> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = new User(key);

            User curr = _users.putIfAbsent(key, user);
            if (curr != null) {
                // User with public key already exists
                responseObserver
                        .onError(Status.INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                _manager.save(user.toJson());
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Invalid Public Key").asRuntimeException());
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            // Should never happen
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        }
    }

    @Override
    public void post(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already	 exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _manager.save(announcement.toJson("Post"));
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            // Should never happen
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Invalid Key Provided").asRuntimeException());
        }

    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            Announcement announcement = generateAnnouncement(request, _generalBoard);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _manager.save(announcement.toJson("PostGeneral"));
                _generalBoard.post(announcement);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            // Should never happen
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            responseObserver
                    .onError(Status.INVALID_ARGUMENT.withDescription("Invalid Key Provided").asRuntimeException());
        }
    }

    public void addUser(PublicKey key) throws NullUserException, NullPublicKeyException {
        User user = new User(key);
        _users.put(key, user);
    }

    public void addAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references, int sequencer)
            throws CommonDomainException {

        var refs = getListOfReferences(references);
        var user = _users.get(key);
        var board = user.getUserBoard();

        var announcement = new Announcement(signature, user, message, refs, sequencer, board);
        board.post(announcement);
        _announcements.put(announcement.getHash(), announcement);
    }

    public void addGeneralAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references, int sequencer)
            throws CommonDomainException {

        var refs = getListOfReferences(references);
        var user = _users.get(key);
        var board = _generalBoard;

        var announcement = new Announcement(signature, user, message, refs, sequencer, board);
        _generalBoard.post(announcement);
        _announcements.put(announcement.getHash(), announcement);
    }

    public void setCounter(int counter) {
        _counter.set(counter);
    }

    public ConcurrentHashMap<PublicKey, User> getUsers() {
        return _users;
    }

    public ConcurrentHashMap<String, Announcement> getAnnouncements() {
        return _announcements;
    }

}
