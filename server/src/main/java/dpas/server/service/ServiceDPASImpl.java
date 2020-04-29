package dpas.server.service;

import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidReferenceException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
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
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import static dpas.common.domain.utils.CryptographicConstants.ASYMMETRIC_KEY_ALGORITHM;
import static io.grpc.Status.INVALID_ARGUMENT;


@Deprecated
public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    protected ConcurrentHashMap<String, Announcement> _announcements;
    protected ConcurrentHashMap<PublicKey, User> _users;
    protected GeneralBoard _generalBoard;

    public ServiceDPASImpl() {
        super();
        _announcements = new ConcurrentHashMap<>();
        _users = new ConcurrentHashMap<>();
        _generalBoard = new GeneralBoard();
    }

    @Override
    public void register(RegisterRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            var user = User.fromRequest(request);

            var curr = _users.putIfAbsent(user.getPublicKey(), user);
            if (curr != null) {
                //User with public key already exists
                responseObserver.onError(INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                responseObserver.onNext(MacReply.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void post(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {

            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(MacReply.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }
    }

    @Override
    public void postGeneral(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, _generalBoard);

            var curr = _announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _generalBoard.post(announcement);
                responseObserver.onNext(MacReply.newBuilder().build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        }

    }

    @Override
    public void read(ReadRequest request, StreamObserver<ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

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

    protected Set<Announcement> getReferences(List<String> referenceIDs) throws InvalidReferenceException {
        // add all references to lists of references
        var references = new HashSet<Announcement>();
        for (var reference : referenceIDs) {
            var announcement = _announcements.get(reference);
            if (announcement == null) {
                throw new InvalidReferenceException("Invalid Reference: reference provided does not exist");
            }
            if (!references.add(announcement)) {
                //Repeated reference
                throw new InvalidReferenceException("Invalid Reference: Reference is repeated");
            }
        }
        return references;
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, AnnouncementBoard board) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = request.getMessage();

        return new Announcement(signature, _users.get(key), message, getReferences(request.getReferencesList()), board, request.getSeq());
    }

    protected Announcement generateAnnouncement(Contract.Announcement request) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = request.getMessage();

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, message, getReferences(request.getReferencesList()), user.getUserBoard(), request.getSeq());
    }
}
