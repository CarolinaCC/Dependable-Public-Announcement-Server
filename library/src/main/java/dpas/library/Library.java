package dpas.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.*;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ByteUtils;
import dpas.utils.ContractGenerator;
import dpas.utils.ErrorGenerator;
import dpas.utils.MacVerifier;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;


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
        GetSeqRequest request = GetSeqRequest.newBuilder().build();
        try {
            String nonce = UUID.randomUUID().toString();
            request = Contract.GetSeqRequest.newBuilder()
                    .setNonce(nonce)
                    .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                    .build();
            var reply = _stub.getSeq(request);

            if (!(MacVerifier.verifyMac(_serverKey, reply, request))) {
                System.out.println("Unable to authenticate server response");
                System.out.println("Library will now shutdown");
                System.exit(1);
            }
            return reply.getSeq() + 1;
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getNonce().getBytes(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return -1;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("An unrecoverable error has ocurred: " + e.getMessage());
            System.out.println("Library will now shutdown");
            System.exit(1);
        }
        return -1;
    }

    private long getSeqGeneral() {
        GetSeqRequest request = GetSeqRequest.newBuilder().build();
        try {
            String nonce = UUID.randomUUID().toString();
            request = Contract.GetSeqRequest.newBuilder()
                    .setNonce(nonce)
                    .build();
            var reply = _stub.getSeqGeneral(request);

            if (!(MacVerifier.verifyMac(_serverKey, reply, nonce))) {
                System.out.println("Unable to authenticate server response");
                System.out.println("Library will now shutdown");
                System.exit(1);
            }
            return reply.getSeq() + 1;
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getNonce().getBytes(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                System.out.println("Library will now shutdown");
                return -1;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("An unrecoverable error has ocurred: " + e.getMessage());
            System.out.println("Library will now shutdown");
            System.exit(1);
        }
        return -1;
    }


    public void register(PublicKey publicKey, PrivateKey privkey) {
        RegisterRequest request = null;
        try {
            request = ContractGenerator.generateRegisterRequest(publicKey, privkey);
            var reply = _stub.register(request);

            if (!MacVerifier.verifyMac(request, reply, _serverKey)) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getMac().toByteArray(), _serverKey)) {
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
            if (!verifyError(e, request.getSignature().toByteArray(), _serverKey)) {
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
            if (!verifyError(e, request.getSignature().toByteArray(), _serverKey)) {
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

    public Announcement[] validateReadResponse(ReadRequest request, ReadReply reply) throws GeneralSecurityException {
        try {
            if (!MacVerifier.verifyMac(_serverKey, ByteUtils.toByteArray(request), reply.getMac().toByteArray())) {
                System.out.println("An error occurred: Unable to validate server response");
                System.exit(1);
            }
        } catch (IOException e) {
            System.out.println("An io error occurred");
            return new Announcement[0];
        }
        var a = new Announcement[reply.getAnnouncementsCount()];
        reply.getAnnouncementsList().toArray(a);
        return a;
    }

    public Announcement[] read(PublicKey publicKey, int number) {
        var request = ReadRequest.newBuilder().build();
        try {
            request = ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .setNonce(UUID.randomUUID().toString())
                    .setNumber(number)
                    .build();
            var reply = _stub.read(request);
            return validateReadResponse(request, reply);
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getNonce().getBytes(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return new Announcement[0];
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            return new Announcement[0];
        } catch (GeneralSecurityException e) {
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
            return new Announcement[0];
        }
    }

    public Announcement[] readGeneral(int number) {
        var request = ReadRequest.newBuilder().build();
        try {
            request = ReadRequest.newBuilder()
                    .setNonce(UUID.randomUUID().toString())
                    .setNumber(number)
                    .build();
            ReadReply reply = _stub.readGeneral(request);
            return validateReadResponse(request, reply);
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getNonce().getBytes(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return new Announcement[0];
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            return new Announcement[0];
        } catch (GeneralSecurityException e) {
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
            return new Announcement[0];
        }
    }

    private boolean verifyError(StatusRuntimeException e, byte[] request, PublicKey key) {
        if (e.getTrailers() == null) {
            return false;
        }
        var trailers = e.getTrailers();

        if (trailers.get(ErrorGenerator.contentKey) == null) {
            return false;
        }

        if (trailers.get(ErrorGenerator.macKey) == null) {
            return false;
        }

        if (!Arrays.equals(request, trailers.get(ErrorGenerator.contentKey))) {
            return false;
        }

        return MacVerifier.verifyMac(key, e);
    }
}
