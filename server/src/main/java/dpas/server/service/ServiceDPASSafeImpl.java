package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidSeqException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
import dpas.server.persistence.PersistenceManager;
import dpas.server.security.SecurityManager;
import dpas.server.security.exception.IllegalMacException;
import dpas.utils.CipherUtils;
import dpas.utils.ContractGenerator;
import dpas.utils.ErrorGenerator;
import dpas.utils.MacGenerator;
import io.grpc.stub.StreamObserver;

import javax.json.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.stream.Collectors;

import static io.grpc.Status.*;

public class ServiceDPASSafeImpl extends ServiceDPASPersistentImpl {
    private final PrivateKey _privateKey;
    private final SecurityManager _securityManager;

    public ServiceDPASSafeImpl(PersistenceManager manager, PrivateKey privKey, SecurityManager securityManager) {
        super(manager);
        _privateKey = privKey;
        _securityManager = securityManager;
    }

    //Use with tests only
    public ServiceDPASSafeImpl(PrivateKey privKey, SecurityManager securityManager) {
        super(null);
        _privateKey = privKey;
        _securityManager = securityManager;
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(_users.containsKey(key))) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User with public key does not exist", request, _privateKey));
            } else {

                var announcements = _users.get(key).getUserBoard().read(request.getNumber());
                var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .addAllAnnouncements(announcementsGRPC)
                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, _privateKey)))
                        .build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            var announcements = _generalBoard.read(request.getNumber());
            var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .addAllAnnouncements(announcementsGRPC)
                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, _privateKey)))
                    .build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateRequest(request);

            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = new User(pubKey);
            var curr = _users.putIfAbsent(pubKey, user);
            if (curr == null) {
                save(user.toJson());
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();

        } catch (CommonDomainException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        }
    }


    @Override
    public void post(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, _privateKey);

            var curr = _announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr == null) {
                //Announcement with that identifier does not exist yet
                save(announcement.toJson("Post"));
                announcement.getUser().getUserBoard().post(announcement);
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }

    }

    @Override
    public void postGeneral(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, _generalBoard, _privateKey);

            var curr = _announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr == null) {
                //Announcement with that identifier does not exist yet
                save(announcement.toJson("PostGeneral"));
                _generalBoard.post(announcement);
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void getSeq(Contract.GetSeqRequest request, StreamObserver<Contract.GetSeqReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            var user = _users.get(key);
            if (user == null) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User with that public key does not exist", request, _privateKey));
                return;
            }
            long seq = user.getUserBoard().getSeq();
            responseObserver.onNext(ContractGenerator.generateSeqReply(seq, request.getNonce(), _privateKey, key));
            responseObserver.onCompleted();
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        }
    }

    @Override
    public void getSeqGeneral(Contract.GetSeqRequest request, StreamObserver<Contract.GetSeqReply> responseObserver) {
        try {
            long seq = _generalBoard.getSeq();
            responseObserver.onNext(ContractGenerator.generateSeqReply(seq, request.getNonce(), _privateKey));
            responseObserver.onCompleted();
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        }
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, AnnouncementBoard board, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey), StandardCharsets.UTF_8);
        return new Announcement(signature, _users.get(key), message, getReferences(request.getReferencesList()), board, request.getSeq());
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey), StandardCharsets.UTF_8);

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, message, getReferences(request.getReferencesList()), user.getUserBoard(), request.getSeq());
    }

    //Don't want to save when testing
    private void save(JsonObject object) throws IOException {
        if (_manager != null) {
            _manager.save(object);
        }
    }
}