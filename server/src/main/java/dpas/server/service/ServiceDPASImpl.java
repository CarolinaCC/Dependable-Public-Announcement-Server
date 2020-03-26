package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidReferenceException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;


public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    protected ConcurrentHashMap<String, Announcement> _announcements;
    protected ConcurrentHashMap<PublicKey, User> _users;
    protected GeneralBoard _generalBoard;
    protected AtomicInteger _counter = new AtomicInteger(0);


    public ServiceDPASImpl(PublicKey pubKey) {
        super();
        _announcements = new ConcurrentHashMap<>();
        _users = new ConcurrentHashMap<>();
        _generalBoard = new GeneralBoard();
    }

    @Override
    public void register(RegisterRequest request, StreamObserver<Empty> responseObserver) {
        try {
            var user = User.fromRequest(request);

            var curr = _users.putIfAbsent(user.getPublicKey(), user);
            if (curr != null) {
                //User with public key already exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
        }
    }

    @Override
    public void post(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {

            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
        }
    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, _generalBoard);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _generalBoard.post(announcement);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
        }

    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(_users.containsKey(key))) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("User with public key does not exist")
                        .asRuntimeException());
            } else {

                var announcements = _users.get(key).getUserBoard().read(request.getNumber());
                var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

                responseObserver.onNext(Contract.ReadReply.newBuilder().addAllAnnouncements(announcementsGRPC).build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(Status.INVALID_ARGUMENT.withDescription(e.getMessage()).withCause(e).asRuntimeException());
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            var announcements = _generalBoard.read(request.getNumber());
            var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

            responseObserver.onNext(Contract.ReadReply.newBuilder().addAllAnnouncements(announcementsGRPC).build());
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
            references.add(announcement);
        }
        return references;
    }

    protected Announcement generateAnnouncement(Contract.PostRequest request, AnnouncementBoard board) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = request.getMessage();

        return new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), board);
    }

    protected Announcement generateAnnouncement(Contract.PostRequest request) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = request.getMessage();

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, message, getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), user.getUserBoard());
    }
}
