package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.UserBoard;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;


public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    protected ConcurrentHashMap<String, Announcement> _announcements;
    protected ConcurrentHashMap<PublicKey, User> _users;
    protected GeneralBoard _generalBoard;


    public ServiceDPASImpl() {
        super();
        this._announcements = new ConcurrentHashMap<>();
        this._users = new ConcurrentHashMap<>();
        this._generalBoard = new GeneralBoard();
    }

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
        } catch (Exception e) {
            replyObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
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

        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
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

        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
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

                ArrayList<Contract.Announcement> announcementsGRPC = new ArrayList<Contract.Announcement>();

                for (Announcement announcement : announcements) {
                    announcementsGRPC.add(announcement.toContract());
                }

                responseObserver.onNext(Contract.ReadReply.newBuilder().addAllAnnouncements(announcementsGRPC)
                        .build());

                responseObserver.onCompleted();
            }

        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription(e.getMessage())
                    .withCause(e)
                    .asRuntimeException());
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {

            int numberToRead = request.getNumber();
            ArrayList<Announcement> announcements = _generalBoard.read(numberToRead);
            ArrayList<Contract.Announcement> contractAnnouncements = new ArrayList<Contract.Announcement>();

            for (Announcement announcement : announcements) {
                contractAnnouncements.add(announcement.toContract());
            }

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .addAllAnnouncements(contractAnnouncements)
                    .build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT
                    .withDescription(e.getMessage())
                    .withCause(e)
                    .asRuntimeException());
        }
    }


    protected ArrayList<Announcement> getListOfReferences(List<String> referenceIDs) throws InvalidReferenceException {
        // add all references to lists of references
        var references = new ArrayList<Announcement>();
        for (var reference : referenceIDs) {
            var announcement = _announcements.get(reference);
            if (announcement == null) {
                throw new InvalidReferenceException("Invalid Reference: reference provided does not exist");
            }
        }
        return references;
    }
}
