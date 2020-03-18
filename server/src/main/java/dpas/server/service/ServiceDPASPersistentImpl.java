package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.User;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class ServiceDPASPersistentImpl extends ServiceDPASImpl {
    private PersistenceManager _manager;

    public ServiceDPASPersistentImpl(PersistenceManager manager) {
        super();
        this._manager = manager;
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<Empty> replyObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            String username = request.getUsername();
            User user = new User(username, key);

            User curr = _users.putIfAbsent(key, user);
            if (curr != null) {
                //User with public key already exists
                replyObserver.onError(Status.INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                _manager.save(registerToJSON(key, username));
                replyObserver.onNext(Empty.newBuilder().build());
                replyObserver.onCompleted();
            }
        } catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            replyObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Public Key").asRuntimeException());
        } catch (NullUsernameException e) {
            replyObserver.onError(Status.INVALID_ARGUMENT.withDescription("Null Username").asRuntimeException());
        } catch (NullUserException e) {
            //Should Never Happen
            replyObserver.onError(Status.INVALID_ARGUMENT.withDescription("Null User For Board").asRuntimeException());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void post(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = _users.get(key);
            byte[] signature = request.getSignature().toByteArray();
            String message = request.getMessage();


            Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()));
            // post announcement
            user.getUserBoard().post(announcement);
            _announcements.put(announcement.getIdentifier(), announcement);
            _manager.save(postToJSON(key, user.getUsername(), signature, message, announcement.getIdentifier(),
                    request.getReferencesList()));

            responseObserver.onNext(Empty.newBuilder().build());
            responseObserver.onCompleted();

        } catch (InvalidSignatureException | NullSignatureException | SignatureException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Signature").asRuntimeException());
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Public Key").asRuntimeException());
        } catch (InvalidMessageSizeException | NullMessageException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Message").asRuntimeException());
        } catch (NullUserException | InvalidUserException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid User").asRuntimeException());
        } catch (InvalidReferenceException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Announcement Reference").asRuntimeException());
        } catch (NullAnnouncementException | IOException e) {
            //Should never happen
            e.printStackTrace();
        }

    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            byte[] signature = request.getSignature().toByteArray();
            String message = request.getMessage();

            User user = _users.get(key);
            Announcement announcement = new Announcement(signature, user, message,
                    getListOfReferences(request.getReferencesList()));

            synchronized (this) {
                _generalBoard.post(announcement);
            }

            _announcements.put(announcement.getIdentifier(), announcement);

            _manager.save(postGeneralToJSON(key, user.getUsername(), signature, message, announcement.getIdentifier(),
                    request.getReferencesList()));

            responseObserver.onNext(Empty.newBuilder().build());
            responseObserver.onCompleted();

        } catch (InvalidSignatureException | NullSignatureException | SignatureException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Signature").asRuntimeException());
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Public Key").asRuntimeException());
        } catch (InvalidMessageSizeException | NullMessageException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Message").asRuntimeException());
        } catch (NullUserException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid User").asRuntimeException());
        } catch (InvalidReferenceException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Invalid Announcement Reference").asRuntimeException());
        } catch (NullAnnouncementException | IOException e) {
            //Should never happen
            e.printStackTrace();
        }
    }

    public String registerToJSON(PublicKey key, String user) {
        return "{\n"
                + "\"Type\" : \"Register\",\n "
                + "\"PublicKey : \"" + Base64.getEncoder().encodeToString(key.getEncoded()) + "\"\n"
                + "\"User\" : \"" + user + "\"\n}";
    }

    public String postToJSON(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {
        StringBuilder builder = new StringBuilder();
        String prefix = "";
        for (String reference : references) {
            builder.append(prefix);
            prefix = ",";
            builder.append(reference).append(", ");
        }
        return "{\n"
                + "\"Type\" : \"Post\",\n"
                + "\"PublicKey\" : \"" + Base64.getEncoder().encodeToString(key.getEncoded()) + "\"\n"
                + "\"User\" : \"" + user + "\"\n"
                + "\"Signature\" : \"" + Base64.getEncoder().encodeToString(signature) + "\"\n"
                + "\"Message\" : \"" + message + "\"\n"
                + "\"Identifier\" : \"" + identifier + "\"\n"
                + "\"References\" : [" + builder.toString() + "]\n}";
    }


    public String postGeneralToJSON(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {
        StringBuilder builder = new StringBuilder();
        String prefix = "";
        for (String reference : references) {
            builder.append(prefix);
            prefix = ",";
            builder.append(reference).append(", ");
        }
        return "{\n"
                + "\"Type\" : \"PostGeneral\",\n"
                + "\"PublicKey\" : \"" + Base64.getEncoder().encodeToString(key.getEncoded()) + "\"\n"
                + "\"User\" : \"" + user + "\"\n"
                + "\"Signature\" : \"" + Base64.getEncoder().encodeToString(signature) + "\"\n"
                + "\"Message\" : " + "\"" + message + "\"\n"
                + "\"Identifier\" : \"" + identifier + "\"\n"
                + "\"References\" : [" + builder.toString() + "]\n}";
    }

    public void addUser (String username, PublicKey key) throws NullUserException, NullPublicKeyException, NullUsernameException {
        User user = new User(username, key);
        _users.put(key, user);
    }

    public void addAnnouncement (String message, PublicKey key, byte[] signature,
                                 ArrayList <String> references) throws InvalidKeyException, NoSuchAlgorithmException, NullAnnouncementException, NullMessageException, SignatureException, InvalidSignatureException, NullSignatureException, NullUserException, InvalidMessageSizeException, InvalidUserException, InvalidReferenceException {
        Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(references));
        // post announcement
        _users.get(key).getUserBoard().post(announcement);
        _announcements.put(announcement.getIdentifier(), announcement);
    }

    public void addGeneralAnnouncement (String message, PublicKey key, byte[] signature,
                                        ArrayList <String> references) throws InvalidKeyException, NoSuchAlgorithmException, NullAnnouncementException, NullMessageException, SignatureException, InvalidSignatureException, NullSignatureException, NullUserException, InvalidMessageSizeException, InvalidReferenceException {
        Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(references));
        // post announcement
        _generalBoard.post(announcement);
        _announcements.put(announcement.getIdentifier(), announcement);
    }

}
