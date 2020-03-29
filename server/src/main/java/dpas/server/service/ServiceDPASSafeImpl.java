package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.SessionManager;
import dpas.utils.bytes.ContractUtils;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import java.util.Random;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import static io.grpc.Status.UNAVAILABLE;

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
        /*
        String sessionNonce = request.getSessionNonce();
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] mac = request.getMac().toByteArray();

        Random rand = new Random();
        int seqNumber = rand.nextInt();

        Contract.ServerHello reply = Contract.ServerHello.newBuilder().setSessionNonce(sessionNonce).setMac().setSeq(seqNumber).build()
         */
    }

    @Override
    public void safePost(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        try {
            byte[] content = ContractUtils.toByteArray(request);
            byte[] mac = request.getMac().toByteArray();
            String sessionNonce = request.getSessionNonce();
            long seq = request.getSeq();
            _sessionManager.validateSessionRequest(sessionNonce, mac, content, seq);
            //TODO REST
        } catch (IOException e) {
            //TODO
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
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


}
