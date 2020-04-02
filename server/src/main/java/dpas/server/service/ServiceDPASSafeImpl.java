package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.server.session.exception.IllegalMacException;
import dpas.utils.handler.ErrorGenerator;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.exception.SessionException;
import dpas.server.session.SessionManager;
import dpas.utils.CipherUtils;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import javax.json.JsonObject;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import static io.grpc.Status.*;

public class ServiceDPASSafeImpl extends ServiceDPASPersistentImpl {
    private PrivateKey _privateKey;
    private SessionManager _sessionManager;

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
    public void newSession(Contract.ClientHello request, StreamObserver<Contract.ServerHello> responseObserver) {
        try {
            if (!MacVerifier.verifyMac(request)) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "Invalid Mac", request, _privateKey));
                return;
            }

            String sessionNonce = request.getSessionNonce();
            PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            long seq = _sessionManager.createSession(publicKey, sessionNonce);

            responseObserver.onNext(ContractGenerator.generateServerHello(_privateKey, seq, sessionNonce));
            responseObserver.onCompleted();

        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT,"Invalid security values provided", request, _privateKey));
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "Unspecified Error at server side", request, _privateKey));
        } catch(IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }


    @Override
    public void safePost(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        try {
            long seq = _sessionManager.validateSessionRequest(request);
            String sessionNonce = request.getSessionNonce();
            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                save(announcement.toJson("Post"));
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(ContractGenerator.generatePostReply(_privateKey, sessionNonce, seq));
                responseObserver.onCompleted();
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request , _privateKey));
        }
    }

    @Override
    public void safePostGeneral(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        try {
            long seq = _sessionManager.validateSessionRequest(request);
            String sessionNonce = request.getSessionNonce();
            Announcement announcement = generateAnnouncement(request, _generalBoard);
            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                save(announcement.toJson("PostGeneral"));
                _generalBoard.post(announcement);
                responseObserver.onNext(ContractGenerator.generatePostReply(_privateKey, sessionNonce, seq));
                responseObserver.onCompleted();
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request , _privateKey));
        }
    }

    @Override
    public void safeRegister(Contract.SafeRegisterRequest request, StreamObserver<Contract.SafeRegisterReply> responseObserver) {
        String nonce = null;
        try {
            nonce = request.getSessionNonce();
            long nextSeq = _sessionManager.validateSessionRequest(request);

            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            var user = new User(pubKey);
            var curr = _users.putIfAbsent(user.getPublicKey(), user);
            if (curr != null) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User Already Exists", request, _privateKey));
            } else {
                save(user.toJson());
                responseObserver.onNext(ContractGenerator.generateRegisterReply(nonce, nextSeq, _privateKey));
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request , _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        }
    }

    @Override
    public void goodbye(Contract.GoodByeRequest request, StreamObserver<Empty> responseObserver) {
        try {
            _sessionManager.validateSessionRequest(request);
            _sessionManager.removeSession(request.getSessionNonce());
            responseObserver.onNext(Empty.newBuilder().build());
            responseObserver.onCompleted();
        } catch (SessionException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
        } catch (IOException | GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (IllegalArgumentException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<Empty> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }


    @Override
    public void post(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Empty> responseObserver) {
        responseObserver.onError(UNAVAILABLE.withDescription("Endpoint Not Active").asRuntimeException());
    }

    protected Announcement generateAnnouncement(Contract.SafePostRequest request, AnnouncementBoard board) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decipher(request.getMessage().toByteArray(), _privateKey), StandardCharsets.UTF_8);

        return new Announcement(signature, _users.get(key), message, getReferences(request.getReferencesList()), _counter.getAndIncrement(), board);
    }

    protected Announcement generateAnnouncement(Contract.SafePostRequest request) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decipher(request.getMessage().toByteArray(), _privateKey), StandardCharsets.UTF_8);

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, message, getReferences(request.getReferencesList()), _counter.getAndIncrement(), user.getUserBoard());
    }

    public SessionManager getSessionManager() {
        return _sessionManager;
    }

    //Don't want to save when testing
    private void save(JsonObject object) throws IOException {
        if (_manager != null) {
            _manager.save(object);
        }
    }
}