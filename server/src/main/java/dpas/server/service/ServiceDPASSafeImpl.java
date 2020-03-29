package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.SessionException;
import dpas.server.session.SessionManager;
import dpas.utils.bytes.ContractUtils;
import dpas.utils.bytes.CypherUtils;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import static io.grpc.Status.*;

public class ServiceDPASSafeImpl extends ServiceDPASImpl {
    private PublicKey _publicKey;
    private PrivateKey _privateKey;
    private PersistenceManager _persistenceManager;
    private SessionManager _sessionManager;

    public ServiceDPASSafeImpl(PersistenceManager manager, PublicKey pubKey, PrivateKey privKey, SessionManager sessionManager) {
        _persistenceManager = manager;
        _publicKey = pubKey;
        _privateKey = privKey;
        _sessionManager = sessionManager;
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

    @Override
    public void newSession(Contract.ClientHello request, StreamObserver<Contract.ServerHello> responseObserver) {

        try {
            String sessionNonce = request.getSessionNonce();
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            byte[] clientMac = request.getMac().toByteArray();

            //Verify client's mac with its public key
            String contentClient = sessionNonce + pubKey;
            Cipher cipherClient = Cipher.getInstance("RSA");
            cipherClient.init(Cipher.DECRYPT_MODE, pubKey);
            byte[] plaintextBytes = cipherClient.doFinal(clientMac);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHashClient = digest.digest(contentClient.getBytes());

            if (!Arrays.equals(encodedHashClient, plaintextBytes))
                throw new IllegalArgumentException("Invalid Client Hmac");

            _sessionManager.createSession(pubKey, sessionNonce);

            //Generate server's mac with its private key
            long seqNumber = new SecureRandom().nextLong();
            String reply = sessionNonce + seqNumber;

            Cipher cipherServer = Cipher.getInstance("RSA");
            cipherServer.init(Cipher.ENCRYPT_MODE, _privateKey);
            byte[] serverMac = cipherServer.doFinal(reply.getBytes());

            responseObserver.onNext(Contract.ServerHello.newBuilder().setSessionNonce(sessionNonce).setMac(ByteString.copyFrom(serverMac)).setSeq((int) seqNumber).build());
            responseObserver.onCompleted();

        } catch (IllegalArgumentException e) {
            responseObserver.onError(ALREADY_EXISTS.withDescription("Session already exists").asRuntimeException());
        } catch (GeneralSecurityException e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription("Invalid Key").asRuntimeException());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }
    }


    @Override
    public void safePost(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        try {
            long seq = validatePostRequest(request);
            String sessionNonce = request.getSessionNonce();
            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already	 exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _persistenceManager.save(announcement.toJson("Post"));
                announcement.getUser().getUserBoard().post(announcement);
                responseObserver.onNext(generatePostReply(sessionNonce, seq));
                responseObserver.onCompleted();
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(CANCELLED.withDescription("Invalid values provided, could not decipher").asRuntimeException());
        } catch (IOException e) {
            responseObserver.onError(CANCELLED.withDescription("An Error ocurred in the server").asRuntimeException());
        } catch (CommonDomainException e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (SessionException e) {
            responseObserver.onError(UNAUTHENTICATED.withDescription("Could not validate request").asRuntimeException());
        }
    }

    @Override
    public void safePostGeneral(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        try {
            long seq = validatePostRequest(request);
            String sessionNonce = request.getSessionNonce();
            Announcement announcement = generateAnnouncement(request, _generalBoard);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _persistenceManager.save(announcement.toJson("PostGeneral"));
                _generalBoard.post(announcement);
                responseObserver.onNext(generatePostReply(sessionNonce, seq));
                responseObserver.onCompleted();
            }
        } catch (GeneralSecurityException e) {
            responseObserver.onError(CANCELLED.withDescription("Invalid values provided, could not decipher").asRuntimeException());
        } catch (IOException e) {
            responseObserver.onError(CANCELLED.withDescription("An Error ocurred in the server").asRuntimeException());
        } catch (CommonDomainException e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (SessionException e) {
            responseObserver.onError(UNAUTHENTICATED.withDescription("Could not validate request").asRuntimeException());
        }
    }

    @Override
    public void safeRegister(Contract.SafeRegisterRequest request, StreamObserver<Contract.SafeRegisterReply> responseObserver) {
        try {
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            String nonce = request.getSessionNonce();
            long nextSeq = _sessionManager.validateSessionRequest(
                    nonce,
                    request.getMac().toByteArray(),
                    ContractUtils.toByteArray(request),
                    request.getSeq());

            var user = new User(pubKey);
            var curr = _users.putIfAbsent(user.getPublicKey(), user);
            if (curr != null) {
                //User with public key already exists
                responseObserver.onError(INVALID_ARGUMENT.withDescription("User Already Exists").asRuntimeException());
            } else {
                _persistenceManager.save(user.toJson());
                byte[] replyMac = ContractUtils.generateMac(nonce, nextSeq, _privateKey);

                responseObserver.onNext(Contract.SafeRegisterReply.newBuilder()
                        .setMac(ByteString.copyFrom(replyMac))
                        .setSeq(nextSeq)
                        .setSessionNonce(nonce)
                        .build());
                responseObserver.onCompleted();
            }
        } catch (CommonDomainException e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (SessionException e) {
            responseObserver.onError(UNAUTHENTICATED.withDescription("Could not validate request").asRuntimeException());
        } catch (IOException | GeneralSecurityException e) {
            responseObserver.onError(CANCELLED.withDescription("An Error ocurred in the server").asRuntimeException());
        }
    }

    @Override
    public void goodbye(Contract.GoodByeRequest request, StreamObserver<Empty> responseObserver) {
        try {
            String nonce = request.getSessionNonce();
            _sessionManager.validateSessionRequest(
                    nonce,
                    request.getMac().toByteArray(),
                    ContractUtils.toByteArray(request),
                    request.getSeq());
            _sessionManager.removeSession(nonce);
            responseObserver.onNext(Empty.newBuilder().build());
            responseObserver.onCompleted();
        } catch (SessionException e) {
            responseObserver.onError(UNAUTHENTICATED.withDescription("Could not validate request").asRuntimeException());
        } catch (IOException | GeneralSecurityException e) {
            responseObserver.onError(CANCELLED.withDescription("An Error ocurred in the server").asRuntimeException());
        }
    }

    protected Announcement generateAnnouncement(Contract.SafePostRequest request, AnnouncementBoard board) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CypherUtils.decipher(request.getMessage().toByteArray(), _privateKey), StandardCharsets.UTF_8);

        return new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), board);
    }

    protected Announcement generateAnnouncement(Contract.SafePostRequest request) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CypherUtils.decipher(request.getMessage().toByteArray(), _privateKey), StandardCharsets.UTF_8);

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, message, getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), user.getUserBoard());
    }

    private long validatePostRequest(Contract.SafePostRequest request) throws IOException, GeneralSecurityException, SessionException {
        byte[] content = ContractUtils.toByteArray(request);
        byte[] mac = request.getMac().toByteArray();
        String sessionNonce = request.getSessionNonce();
        long seq = request.getSeq();
        return _sessionManager.validateSessionRequest(sessionNonce, mac, content, seq);
    }

    private Contract.SafePostReply generatePostReply(String sessionNonce, long seq) throws GeneralSecurityException, IOException {
        byte[] mac = ContractUtils.generateMac(sessionNonce, seq, _privateKey);
        return Contract.SafePostReply.newBuilder()
                .setSessionNonce(sessionNonce)
                .setSeq(seq)
                .setMac(ByteString.copyFrom(mac))
                .build();
    }

    public SessionManager getSessionManager() {
        return _sessionManager;
    }


}
