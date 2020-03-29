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
import dpas.grpc.contract.Contract.PostRequest;
import dpas.grpc.contract.Contract.ReadReply;
import dpas.grpc.contract.Contract.ReadRequest;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.stub.StreamObserver;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static io.grpc.Status.INVALID_ARGUMENT;
import static io.grpc.Status.UNAVAILABLE;


public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    protected ConcurrentHashMap<String, Announcement> _announcements;
    protected ConcurrentHashMap<PublicKey, User> _users;
    protected GeneralBoard _generalBoard;
    protected AtomicInteger _counter = new AtomicInteger(0);


    public ServiceDPASImpl() {
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
                responseObserver.onError(INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void post(PostRequest request, StreamObserver<Empty> responseObserver) {
        try {

            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void postGeneral(PostRequest request, StreamObserver<Empty> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, _generalBoard);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _generalBoard.post(announcement);
                responseObserver.onNext(Empty.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }

    }

    @Override
    public void read(ReadRequest request, StreamObserver<ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(_users.containsKey(key))) {
                responseObserver.onError(INVALID_ARGUMENT.withDescription("User with public key does not exist")
                        .asRuntimeException());
            } else {

                var announcements = _users.get(key).getUserBoard().read(request.getNumber());
                var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

                responseObserver.onNext(ReadReply.newBuilder().addAllAnnouncements(announcementsGRPC).build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void readGeneral(ReadRequest request, StreamObserver<ReadReply> responseObserver) {

        try {
            var announcements = _generalBoard.read(request.getNumber());
            var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

            responseObserver.onNext(ReadReply.newBuilder().addAllAnnouncements(announcementsGRPC).build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void dhKeyExchange(Contract.ClientHello request, StreamObserver<Contract.ServerHello> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }

    @Override
    public void dhFreshnessProof(Contract.ClientProof request, StreamObserver<Contract.ServerProof> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }

    @Override
    public void safePost(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }

    @Override
    public void safePostGeneral(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }

    @Override
    public void safeRegister(Contract.SafeRegisterRequest request, StreamObserver<Contract.SafeRegisterReply> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
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

    protected Announcement generateAnnouncement(PostRequest request, AnnouncementBoard board) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = request.getMessage();

        return new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), board);
    }

    protected Announcement generateAnnouncement(PostRequest request) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
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
