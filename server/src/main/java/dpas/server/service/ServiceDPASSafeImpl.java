package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.SessionException;
import dpas.server.session.SessionManager;
import dpas.utils.bytes.ContractUtils;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
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
            _sessionManager.createSession(pubKey, sessionNonce);

            //Verify client's mac with its public key
            String contentClient = sessionNonce + pubKey;
            Cipher cipherClient = Cipher.getInstance("RSA");
            cipherClient.init(Cipher.DECRYPT_MODE, pubKey);
            byte[] plaintextBytes = cipherClient.doFinal(clientMac);

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] encodedHashClient = digest.digest(contentClient.getBytes());

            if (!Arrays.equals(encodedHashClient, plaintextBytes))
                throw new IllegalArgumentException("Invalid hmac");

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
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
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
            byte[] content = ContractUtils.toByteArray(request);
            byte[] mac = request.getMac().toByteArray();
            String sessionNonce = request.getSessionNonce();
            long seq = request.getSeq();
            long nextSeq = _sessionManager.validateSessionRequest(sessionNonce, mac, content, seq);
            var announcement = generateAnnouncement(request);

            var curr = _announcements.putIfAbsent(announcement.getHash(), announcement);
            if (curr != null) {
                //Announcement with that identifier already	 exists
                responseObserver.onError(Status.INVALID_ARGUMENT.withDescription("Post Identifier Already Exists").asRuntimeException());
            } else {
                _persistenceManager.save(announcement.toJson("Post"));
                announcement.getUser().getUserBoard().post(announcement);
                Contract.SafePostReply reply = Contract.SafePostReply.newBuilder().setSessionNonce(sessionNonce).setSeq(nextSeq).build();
                byte[] serverMac = ContractUtils.generateMac(sessionNonce, nextSeq, _privateKey);
                responseObserver.onNext(Contract.SafePostReply.newBuilder()
                        .setSessionNonce(sessionNonce)
                        .setSeq(nextSeq)
                        .setMac(ByteString.copyFrom(serverMac))
                        .build());
                responseObserver.onCompleted();
            }
        } catch (IOException | GeneralSecurityException e) {
            responseObserver.onError(CANCELLED.withDescription("An Error ocurred in the server").asRuntimeException());
        } catch (CommonDomainException e) {
            responseObserver.onError(INVALID_ARGUMENT.withDescription(e.getMessage()).asRuntimeException());
        } catch (SessionException e) {
            responseObserver.onError(UNAUTHENTICATED.withDescription("Could not validate request").asRuntimeException());
        }
    }

    @Override
    public void safePostGeneral(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        //TODO
    }

    @Override
    public void safeRegister(Contract.SafeRegisterRequest request, StreamObserver<Contract.SafeRegisterReply> responseObserver) {
        try {
            PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            String nonce = request.getSessionNonce();
            long seq = request.getSeq();
            _sessionManager.validateSessionRequest(nonce,
                    request.getMac().toByteArray(),
                    ContractUtils.toByteArray(request),
                    seq);


        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    protected Announcement generateAnnouncement(Contract.SafePostRequest request, AnnouncementBoard board) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        //TODO
        //String message = request.getMessage();

        return new Announcement(signature, _users.get(key), "message", getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), board);
    }

    protected Announcement generateAnnouncement(Contract.SafePostRequest request) throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        //TODO
        //String message = request.getMessage();

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        return new Announcement(signature, user, "message", getListOfReferences(request.getReferencesList()), _counter.getAndIncrement(), user.getUserBoard());
    }

}
