package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentHashMap;

public class ServiceDPASPersistentImpl extends ServiceDPASImpl {
    private PersistenceManager _manager;

    public ServiceDPASPersistentImpl(PersistenceManager manager) {
        super();
        this._manager = manager;
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<Empty> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            String username = request.getUsername();
            User user = new User(username, key);

            User curr = _users.putIfAbsent(key, user);
            if (curr != null) {
                //User with public key already exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                _manager.save(user.toJson());
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Public Key").asRuntimeException());
        } catch (CommonDomainException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            //Should never happen
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        }
    }

    @Override
    public void post(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {

            Announcement announcement = generateAnnouncement(request);

            _manager.save(announcement.toJson("Post"));
            _announcements.put(announcement.getIdentifier(), announcement);
            announcement.getUser().getUserBoard().post(announcement);

            responseObserver.onNext(Empty.newBuilder().build());
            responseObserver.onCompleted();

        } catch (CommonDomainException | SignatureException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            //Should never happen
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Key Provided").asRuntimeException());
        }

    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            Announcement announcement = generateAnnouncement(request);

            _manager.save(announcement.toJson("PostGeneral"));
            _announcements.put(announcement.getIdentifier(), announcement);
            synchronized (this) {
                _generalBoard.post(announcement);
            }

            responseObserver.onNext(Empty.newBuilder().build());
            responseObserver.onCompleted();

        } catch (CommonDomainException | SignatureException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (IOException e) {
            //Should never happen
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Error on Server Side").asRuntimeException());
        } catch (NoSuchAlgorithmException | InvalidKeyException | InvalidKeySpecException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Key Provided").asRuntimeException());
        }
    }


    public void addUser(String username, PublicKey key) throws NullUserException, NullPublicKeyException, NullUsernameException {
        User user = new User(username, key);
        _users.put(key, user);
    }

    public void addAnnouncement(String message, PublicKey key, byte[] signature,
                                ArrayList<String> references, String identifier) throws InvalidKeyException, NoSuchAlgorithmException, CommonDomainException, SignatureException {

        Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(references), identifier);
        _users.get(key).getUserBoard().post(announcement);
        _announcements.put(announcement.getIdentifier(), announcement);
    }

    public void addGeneralAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references,
                                       String identifier) throws InvalidKeyException, NoSuchAlgorithmException, CommonDomainException, SignatureException {

        Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(references), identifier);
        _generalBoard.post(announcement);
        _announcements.put(announcement.getIdentifier(), announcement);
    }

    public ConcurrentHashMap<PublicKey, User> getUsers() {
        return _users;
    }

    public ConcurrentHashMap<String, Announcement> getAnnouncements() {
        return _announcements;
    }

}
