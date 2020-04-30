package dpas.utils.link;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.MacVerifier;
import dpas.utils.auth.ReplyValidator;
import io.grpc.stub.StreamObserver;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Map;

/**
 * Implementation of authenticated perfect point to point link
 */
public class PerfectStub {
    private final ServiceDPASGrpc.ServiceDPASStub stub;
    private final PublicKey serverKey;

    public PerfectStub(ServiceDPASGrpc.ServiceDPASStub stub, PublicKey serverKey) {
        this.stub = stub;
        this.serverKey = serverKey;
    }

    public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.register(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
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
                register(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void post(Contract.Announcement announcement, StreamObserver<Contract.MacReply> replyObserver) {
        stub.post(announcement, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(serverKey, value, announcement)) {
                    post(announcement, replyObserver);
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
                post(announcement, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void readReliable(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver,
                             Map<String, PublicKey> serverKeys, int quorumSize) {
        stub.read(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                try {
                    if (!ReplyValidator.validateReadReply(request, value, serverKey,
                            CipherUtils.keyFromBytes(request.getPublicKey().toByteArray()), serverKeys, quorumSize)) {
                        readReliable(request, replyObserver, serverKeys, quorumSize);
                    } else {
                        replyObserver.onNext(value);
                    }
                } catch (GeneralSecurityException e) {
                    readReliable(request, replyObserver, serverKeys, quorumSize);
                }
            }

            @Override
            public void onError(Throwable t) {
                //If an error occurred it is either a byzantine client (we don't care about him)
                //The attacker changed the integrity parameters (we must keep trying until the attacker gives up)
                //A byzantine server (since we can't know, we must retry still)
                //Some previous post this depends on or a register hasn't reached the server, we must also retry until it does
                readReliable(request, replyObserver, serverKeys, quorumSize);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void readGeneralReliable(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver,
                                    Map<String, PublicKey> serverKeys, int quorumSize) {
        stub.readGeneral(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!ReplyValidator.validateReadGeneralReply(request, value, serverKey, serverKeys, quorumSize)) {
                    readGeneralReliable(request, replyObserver, serverKeys, quorumSize);
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
                readGeneralReliable(request, replyObserver, serverKeys, quorumSize);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void postGeneral(Contract.Announcement announcement, StreamObserver<Contract.MacReply> replyObserver) {

        stub.postGeneral(announcement, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(serverKey, value, announcement)) {
                    postGeneral(announcement, replyObserver);
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
                postGeneral(announcement, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void echoRegister(Contract.EchoRegister request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.echoRegister(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
                    echoRegister(request, replyObserver);
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
                echoRegister(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void echoAnnouncement(Contract.EchoAnnouncement request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.echoAnnouncement(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
                    echoAnnouncement(request, replyObserver);
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
                echoAnnouncement(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void echoAnnouncementGeneral(Contract.EchoAnnouncement request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.echoAnnouncementGeneral(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
                    echoAnnouncementGeneral(request, replyObserver);
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
                echoAnnouncementGeneral(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void readyRegister(Contract.ReadyRegister request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.readyRegister(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
                    readyRegister(request, replyObserver);
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
                readyRegister(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void readyAnnouncement(Contract.ReadyAnnouncement request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.readyAnnouncement(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
                    readyAnnouncement(request, replyObserver);
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
                readyAnnouncement(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public void readyAnnouncementGeneral(Contract.ReadyAnnouncement request, StreamObserver<Contract.MacReply> replyObserver) {
        stub.readyAnnouncementGeneral(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!MacVerifier.verifyMac(request, value, serverKey)) {
                    readyAnnouncementGeneral(request, replyObserver);
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
                readyAnnouncementGeneral(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    public PublicKey getServerKey() {
        return serverKey;
    }

    public String getServerId() {
        return Base64.getEncoder().encodeToString(serverKey.getEncoded());
    }

    @Deprecated
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver) {
        stub.read(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                try {
                    if (!ReplyValidator.validateReadReply(request, value, serverKey, CipherUtils.keyFromBytes(request.getPublicKey().toByteArray()))) {
                        read(request, replyObserver);
                    } else {
                        replyObserver.onNext(value);
                    }
                } catch (GeneralSecurityException e) {
                    read(request, replyObserver);
                }
            }

            @Override
            public void onError(Throwable t) {
                //If an error occurred it is either a byzantine client (we don't care about him)
                //The attacker changed the integrity parameters (we must keep trying until the attacker gives up)
                //A byzantine server (since we can't know, we must retry still)
                //Some previous post this depends on or a register hasn't reached the server, we must also retry until it does
                read(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }

    @Deprecated
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> replyObserver) {
        stub.readGeneral(request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                //If we can't verify the response then either the attacker changed it (must retry until he stops)
                //Or the server is byzantine (since we can't know must keep trying)
                //Since the operation is idempotent resending to a correct server has no impact
                if (!ReplyValidator.validateReadGeneralReply(request, value, serverKey)) {
                    readGeneral(request, replyObserver);
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
                readGeneral(request, replyObserver);
            }

            @Override
            public void onCompleted() {
                replyObserver.onCompleted();
            }
        });
    }
}
