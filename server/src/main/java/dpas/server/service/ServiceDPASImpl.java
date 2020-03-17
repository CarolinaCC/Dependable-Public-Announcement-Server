package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.ProtocolStringList;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.UserBoard;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import com.google.protobuf.Empty;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;


public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    private ConcurrentHashMap<String, Announcement> _announcements = new ConcurrentHashMap<>();
    private ConcurrentHashMap<PublicKey, User> _users = new ConcurrentHashMap<>();
    private GeneralBoard _generalBoard = new GeneralBoard();

    @Override
    public void register(RegisterRequest request, StreamObserver<Empty> replyObserver) {
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
        } catch (NullAnnouncementException e) {
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

            Announcement announcement = new Announcement(signature, _users.get(key), message,
                    getListOfReferences(request.getReferencesList()));

            synchronized (this) {
                _generalBoard.post(announcement);
            }

            _announcements.put(announcement.getIdentifier(), announcement);

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
        } catch (NullAnnouncementException e) {
            //Should never happen
            e.printStackTrace();
        }
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(_users.containsKey(key))) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("User with public key does not exist")
                        .asRuntimeException());
            } else {
                User user = _users.get(key);
                int numberToRead = request.getNumber();
                UserBoard userBoard = user.getUserBoard();
                ArrayList<Announcement> announcements = userBoard.read(numberToRead);
                byte[] announcementsBytes = SerializationUtils.serialize(announcements);

                responseObserver.onNext(Contract.ReadReply.newBuilder().setAnnouncements(ByteString.copyFrom(announcementsBytes))
                        .build());

                responseObserver.onCompleted();
            }

        } catch (InvalidNumberOfPostsException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription("Invalid Number of Posts")
                    .asRuntimeException());
        } catch (InvalidKeySpecException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription("Invalid Public Key Provided")
                    .asRuntimeException());
        } catch (NoSuchAlgorithmException e) {
            //Should never happen
            e.printStackTrace();
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {

            int numberToRead = request.getNumber();
            ArrayList<Announcement> announcements = _generalBoard.read(numberToRead);
            byte[] announcementsBytes = SerializationUtils.serialize(announcements);

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setAnnouncements(ByteString.copyFrom(announcementsBytes))
                    .build());
            responseObserver.onCompleted();
        } catch (InvalidNumberOfPostsException e) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription("Invalid Number of Posts")
                    .asRuntimeException());
        }
    }


    private ArrayList<Announcement> getListOfReferences(ProtocolStringList referenceIDs) throws InvalidReferenceException {
        // add all references to lists of references
        var references = new ArrayList<Announcement>();
        for (var reference : referenceIDs) {
            var announcement = _announcements.get(reference);
            if (announcement == null) {
                throw new InvalidReferenceException();
            }
        }
        return references;
    }
}
