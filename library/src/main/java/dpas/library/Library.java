package dpas.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.ReadReply;
import dpas.grpc.contract.Contract.ReadRequest;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.MacVerifier;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.UUID;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;

import static dpas.utils.auth.ReplyValidator.validateReadGeneralReply;
import static dpas.utils.auth.ReplyValidator.validateReadReply;
import static dpas.utils.auth.ReplyValidator.verifyError;

public class Library {

    private final ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private final PublicKey _serverKey;
    private final ManagedChannel _channel;

    public Library(String host, int port, PublicKey serverKey) {
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _serverKey = serverKey;
    }

    public void finish() {
        _channel.shutdown();
    }

    private long getSeq(PublicKey pubKey) {
        var request = ReadRequest.newBuilder().build();
        try {
            String nonce = UUID.randomUUID().toString();
            request = Contract.ReadRequest.newBuilder()
                    .setNonce(nonce)
                    .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                    .setNumber(1)
                    .build();
            var reply = _stub.read(request);

            if (!validateReadReply(request, reply, _serverKey, pubKey)) {
                return -1;
            }
            var a = reply.getAnnouncementsList();
            if (a.size() == 0) {
                return 0;
            } else {
                return a.get(a.size() - 1).getSeq() + 1;
            }

        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request, _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return -1;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        }
        return -1;
    }

    private long getSeqGeneral() {
        var request = ReadRequest.newBuilder().build();
        try {
            String nonce = UUID.randomUUID().toString();
            request = Contract.ReadRequest.newBuilder()
                    .setNonce(nonce)
                    .setNumber(1)
                    .build();
            var reply = _stub.readGeneral(request);

            if (!validateReadGeneralReply(request, reply, _serverKey)) {
                return -1;
            }
            var a = reply.getAnnouncementsList();
            if (a.size() == 0) {
                return 0;
            } else {
                return a.get(a.size() - 1).getSeq() + 1;
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request, _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return -1;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        }
        return -1;
    }


    public void register(PublicKey publicKey, PrivateKey privkey) {
        RegisterRequest request = RegisterRequest.newBuilder().build();
        try {
            request = ContractGenerator.generateRegisterRequest(publicKey, privkey);
            var reply = _stub.register(request);

            if (!MacVerifier.verifyMac(request, reply, _serverKey)) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request, _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        } catch (GeneralSecurityException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        }
    }

    public void post(PublicKey key, char[] message, Announcement[] a, PrivateKey privateKey) {
        Announcement request = Announcement.newBuilder().build();
        try {
            var seq = getSeq(key);
            if (seq == -1) {
                return;
            }
            request = ContractGenerator.generateAnnouncement(_serverKey, key, privateKey,
                    String.valueOf(message),
                    seq, Base64.getEncoder().encodeToString(key.getEncoded()), a);
            var reply = _stub.post(request);

            if (!MacVerifier.verifyMac(_serverKey, reply, request)) {
                System.out.println("An error occurred: Unable to validate server response.");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request, _serverKey)) {
                System.out.println("Unable to validate server response");
                return;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());

        } catch (GeneralSecurityException | CommonDomainException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        }

    }

    public void postGeneral(PublicKey pubKey, char[] message, Announcement[] a, PrivateKey privateKey) {
        Announcement request = Announcement.newBuilder().build();
        try {
            var seq = getSeqGeneral();
            if (seq == -1) {
                return;
            }
            request = ContractGenerator.generateAnnouncement(_serverKey, pubKey, privateKey, String.valueOf(message),
                    seq, GENERAL_BOARD_IDENTIFIER, a);

            var reply = _stub.postGeneral(request);

            if (!MacVerifier.verifyMac(_serverKey, reply, request)) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request, _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        } catch (GeneralSecurityException | CommonDomainException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        }
    }

    public Announcement[] read(PublicKey publicKey, int number) {
        var request = ReadRequest.newBuilder().build();
        try {
            request = ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .setNonce(UUID.randomUUID().toString())
                    .setNumber(number)
                    .build();
            return readReply(request, _stub.read(request), publicKey);

        } catch (StatusRuntimeException e) {
            return readError(e, request);
        }
    }

    public Announcement[] readGeneral(int number) {
        var request = ReadRequest.newBuilder().build();
        try {
            request = ReadRequest.newBuilder()
                    .setNonce(UUID.randomUUID().toString())
                    .setNumber(number)
                    .build();

            return readGeneralReply(request, _stub.readGeneral(request));
        } catch (StatusRuntimeException e) {
            return readError(e, request);
        }
    }

    private Announcement[] readError(StatusRuntimeException e, ReadRequest request) {
        if (!verifyError(e, request, _serverKey)) {
            System.out.println("Unable to authenticate server response");
            return new Announcement[0];
        }
        Status status = e.getStatus();
        System.out.println("An error occurred: " + status.getDescription());
        return new Announcement[0];
    }

    private Announcement[] readReply(ReadRequest request, ReadReply reply, PublicKey authorKey) {
        if (!validateReadReply(request, reply, _serverKey, authorKey)) {
            System.out.println("Unable to authenticate server response");
            return new Announcement[0];
        }
        var a = new Announcement[reply.getAnnouncementsCount()];
        return reply.getAnnouncementsList().toArray(a);
    }

    private Announcement[] readGeneralReply(ReadRequest request, ReadReply reply) {
        if (!validateReadGeneralReply(request, reply, _serverKey)) {
            System.out.println("Unable to authenticate server response");
            return new Announcement[0];
        }
        var a = new Announcement[reply.getAnnouncementsCount()];
        return reply.getAnnouncementsList().toArray(a);
    }

}
