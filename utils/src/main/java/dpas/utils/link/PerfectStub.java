package dpas.utils.link;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.MacVerifier;
import dpas.utils.auth.ReplyValidator;
import io.grpc.stub.StreamObserver;

import java.security.GeneralSecurityException;
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
                if (!ReplyValidator.verifyError(t, announcement, _serverKey)) {
                    //Response was not authenticated, so It must be the attacker or a byzantine server
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

    public void readGeneralWithException(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver) {
        _stub.readGeneral(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!ReplyValidator.validateReadGeneralReply(request, value, _serverKey)) {
                    readGeneralWithException(request, replyObserver);
                } else {
                    replyObserver.onNext(value);
                }
            }

            @Override
            public void onError(Throwable t) {
                if (!ReplyValidator.verifyError(t, request, _serverKey)) {
                    //Response was not authenticated, so It must be the attacker or a byzantine server
                    //Either way retry until obtaining a valid answer
                    readGeneralWithException(request, replyObserver);
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


    public void readWithException(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver) {
        _stub.read(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                try {
                    if (!ReplyValidator.validateReadReply(request, value, _serverKey, CipherUtils.keyFromBytes(request.getPublicKey().toByteArray()))) {
                        readWithException(request, replyObserver);
                    } else {
                        replyObserver.onNext(value);
                    }
                } catch (GeneralSecurityException e) {
                    readWithException(request, replyObserver);
                }
            }

            @Override
            public void onError(Throwable t) {
                if (!ReplyValidator.verifyError(t, request, _serverKey)) {
                    //Response was not authenticated, so It must be the attacker or a byzantine server
                    //Either way retry until obtaining a valid answer
                    readWithException(request, replyObserver);
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

    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver) {
        _stub.readGeneral(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!ReplyValidator.validateReadGeneralReply(request, value, _serverKey)) {
                    readGeneralWithException(request, replyObserver);
                } else {
                    replyObserver.onNext(value);
                }
            }

            @Override
            public void onError(Throwable t) {
                //If an error occurred it is either a byzantine client (we don't care about him)
                //The attacker changed the integrity parameters (we must keep trying until the attacker gives up)
                //A byzantine server (since we can't know, we must retry still)
                //Some previous post this depends on or a register hasn't reached the server, we must also retry until it does
                replyObserver.onError(t);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> replyObserver) {
        _stub.register(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, _serverKey)) {
                    register(request, replyObserver);
                } else {
                    replyObserver.onNext(value);
                }
            }

            @Override
            public void onError(Throwable t) {
                //If an error occurred it is either a byzantine client (we don't care about him)
                //The attacker changed the integrity parameters (we must keep trying until the attacker gives up)
                //A byzantine server (since we can't know, we must retry still)
                //Some previous post this depends on or a register hasn't reached the server, we must also retry until it does
                replyObserver.onError(t);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void registerWithException(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> replyObserver) {
        _stub.register(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, _serverKey)) {
                    registerWithException(request, replyObserver);
                } else {
                    replyObserver.onNext(value);
                }
            }

            @Override
            public void onError(Throwable t) {
                //If an error occurred it is either a byzantine client (we don't care about him)
                //The attacker changed the integrity parameters (we must keep trying until the attacker gives up)
                //A byzantine server (since we can't know, we must retry still)
                //Some previous post this depends on or a register hasn't reached the server, we must also retry until it does
                if (!ReplyValidator.verifyError(t, request, _serverKey)) {
                    //Response was not authenticated, so It must be the attacker or a byzantine server
                    //Either way retry until obtaining a valid answer
                    registerWithException(request, replyObserver);
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
