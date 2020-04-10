package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.SessionManager;
import dpas.server.session.exception.IllegalMacException;
import dpas.server.session.exception.SessionException;
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
    private final SessionManager _sessionManager;

    public ServiceDPASSafeImpl(PersistenceManager manager, PrivateKey privKey, SessionManager sessionManager) {
        super(manager);
        _privateKey = privKey;
        _sessionManager = sessionManager;
    }

    //Use with tests only
    public ServiceDPASSafeImpl(PrivateKey privKey, SessionManager sessionManager) {
        super(null);
        _privateKey = privKey;
        _sessionManager = sessionManager;
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
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            _sessionManager.validateSessionRequest(request);
            var user = new User(pubKey);
            var curr = _users.putIfAbsent(user.getPublicKey(), user);
            if (curr != null) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User Already Exists", request, _privateKey));
            } else {
                save(user.toJson());
                responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        }
    }


    @Override
    public void post(Contract.PostRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            var user = _users.get(key);
            if (user == null) {
                responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, "User does not exist", request, _privateKey));
                return;
            }
            synchronized (user) {
                _sessionManager.validateSessionRequest(request, user.getSeq());

                var announcement = generateAnnouncement(request, _privateKey);

                var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
                if (curr != null) {
                    //Announcement with that identifier already exists
                    responseObserver.onError(INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
                } else {
                    save(announcement.toJson("Post"));
                    announcement.getUser().getUserBoard().post(announcement);
                    user.incrSeq(1);
                    responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
                    responseObserver.onCompleted();
                }
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
        }

    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            var user = _users.get(key);
            if (user == null) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User with that public key does not exist", request, _privateKey));
                return;
            }
            synchronized (user) {
                _sessionManager.validateSessionRequest(request, user.getSeq());

                var announcement = generateAnnouncement(request, _generalBoard, _privateKey);

                var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
                if (curr != null) {
                    //Announcement with that identifier already exists
                    responseObserver.onError(INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
                } else {
                    save(announcement.toJson("PostGeneral"));
                    _generalBoard.post(announcement);
                    user.incrSeq(1);
                    responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
                    responseObserver.onCompleted();
                }
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
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
            synchronized (user) {
                long seq = user.getSeq();
                responseObserver.onNext(ContractGenerator.generateSeqReply(seq, request.getNonce(), _privateKey, key));
                responseObserver.onCompleted();
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        }
    }

    protected Announcement generateAnnouncement(Contract.PostRequest request, AnnouncementBoard board, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey), StandardCharsets.UTF_8);
        return new Announcement(signature, _users.get(key), message, getReferences(request.getReferencesList()), _counter.getAndIncrement(), board);
    }

    protected Announcement generateAnnouncement(Contract.PostRequest request, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey), StandardCharsets.UTF_8);

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, message, getReferences(request.getReferencesList()), _counter.getAndIncrement(), user.getUserBoard());
    }

    //Don't want to save when testing
    private void save(JsonObject object) throws IOException {
        if (_manager != null) {
            _manager.save(object);
        }
    }
}