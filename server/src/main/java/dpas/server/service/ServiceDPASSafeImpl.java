package dpas.server.service;

import com.google.protobuf.Empty;
import dpas.grpc.contract.Contract;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.SessionManager;
import io.grpc.stub.StreamObserver;

import java.security.PrivateKey;
import java.security.PublicKey;

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
    public void dhKeyExchange(Contract.ClientHello request, StreamObserver<Contract.ServerHello> responseObserver) {
        //TODO CATARINA
    }

    @Override
    public void dhFreshnessProof(Contract.ClientProof request, StreamObserver<Contract.ServerProof> responseObserver) {
        //TODO
    }

    @Override
    public void safePost(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        //TODO
    }

    @Override
    public void safePostGeneral(Contract.SafePostRequest request, StreamObserver<Contract.SafePostReply> responseObserver) {
        //TODO
    }

    @Override
    public void safeRegister(Contract.SafeRegisterRequest request, StreamObserver<Contract.SafeRegisterReply> responseObserver) {
        //TODO
    }

}
