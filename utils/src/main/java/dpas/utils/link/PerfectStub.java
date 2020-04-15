package dpas.utils.link;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.auth.ErrorVerifier;
import dpas.utils.auth.MacVerifier;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;

import java.security.PublicKey;

/**
 * Implementation of authenticated perfect point to point link
 */
public class PerfectStub {
    private final ServiceDPASGrpc.ServiceDPASStub _stub;
    private final PublicKey _serverKey;

    public PerfectStub(ServiceDPASGrpc.ServiceDPASStub stub, PublicKey serverKey) {
        _stub = stub;
        _serverKey = serverKey;
    }

    public void post(Contract.Announcement announcement, StreamObserver<Contract.MacReply> replyObserver) {
        _stub.post(announcement, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(_serverKey, value, announcement)) {
                    post(announcement, replyObserver);
                }
                replyObserver.onNext(value);
            }

            @Override
            public void onError(Throwable t) {
                //If an error occurred it is either a byzantine client (we don't care about him)
                //The attacker changed the integrity parameters (we must keep trying until the attacker gives up)
                //A byzantine server (since we can't know, we must retry still)
                //Some previous post this depends on or a register hasn't reached the server, we must also retry until it does
                post(announcement, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void postWithException(Contract.Announcement announcement, StreamObserver<Contract.MacReply> replyObserver) {
        _stub.post(announcement, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(_serverKey, value, announcement)) {
                    postWithException(announcement, replyObserver);
                } else {
                    replyObserver.onNext(value);
                }
            }

            @Override
            public void onError(Throwable t) {
                if (!ErrorVerifier.verifyError(t, announcement.getSignature().toByteArray(), _serverKey)) {
                    //Response was not sent from the server, so It must be the attacker or a byzantine server
                    //Either way retry until obtaining a valid answer
                    postWithException(announcement, replyObserver);
                } else {
                    replyObserver.onError(t);
                }
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }
}