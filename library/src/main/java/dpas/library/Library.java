package dpas.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.*;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import dpas.utils.ErrorGenerator;
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
    private final Map<PublicKey, Session> _sessions;
    private final PublicKey _serverKey;
    private final ManagedChannel _channel;

    public Library(String host, int port, PublicKey serverKey) {
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _sessions = new HashMap<>();
        _serverKey = serverKey;
    }

    public void finish() {
        _channel.shutdown();
    }

    private void newSession(PublicKey pubKey) {
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
            long seq = reply.getSeq() + 1;
            Session session = new Session(seq);
            _sessions.put(pubKey, session);
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getNonce().getBytes(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
            }
            System.out.println("Library will now shutdown");
            System.exit(1);
        } catch (GeneralSecurityException | IOException e) {
            System.out.println("An unrecoverable error has ocurred: " + e.getMessage());
            System.out.println("Library will now shutdown");
            System.exit(1);
        }
    }

    private Session getSession(PublicKey pubKey) {
        if (!_sessions.containsKey(pubKey)) {
            newSession(pubKey);
        }
        return _sessions.get(pubKey);
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
        Session session = null;
        PostRequest request = PostRequest.newBuilder().build();
        try {
            session = getSession(key);
            request = ContractGenerator.generatePostRequest(_serverKey, key, privateKey,
                    String.valueOf(message),
                    session.getSeq(), Base64.getEncoder().encodeToString(key.getEncoded()), a);
            var reply = _stub.post(request);

            if (!MacVerifier.verifyMac(_serverKey, reply, request)) {
                System.out.println("An error occurred: Unable to validate server response.");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getMac().toByteArray(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            if (status.getCode().equals(Status.Code.UNAUTHENTICATED)) {
                System.out.println("Creating a new session and retrying...");
                newSession(key);
                post(key, message, a, privateKey);
            }
        } catch (GeneralSecurityException | CommonDomainException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        } finally {
            if (session != null) {
                session.updateSeq();
            }
        }
    }

    public void postGeneral(PublicKey pubKey, char[] message, Announcement[] a, PrivateKey privateKey) {
        Session session = null;
        PostRequest request = PostRequest.newBuilder().build();
        try {
            session = getSession(pubKey);
            request = ContractGenerator.generatePostRequest(_serverKey, pubKey, privateKey, String.valueOf(message),
                    session.getSeq(), GENERAL_BOARD_IDENTIFIER, a);

            var reply = _stub.postGeneral(request);

            if (!MacVerifier.verifyMac(_serverKey, reply, request)) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getMac().toByteArray(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            // if user doesnt have a vlid session
            if (status.getCode().equals(Status.Code.UNAUTHENTICATED)) {
                System.out.println("Creating new session and retrying...");
                newSession(pubKey);
                postGeneral(pubKey, message, a, privateKey);
            }
        } catch (GeneralSecurityException | CommonDomainException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        } finally {
            if (session != null) {
                session.updateSeq();
            }
        }

    }

    public Announcement[] validateReadResponse(ReadRequest request, ReadReply reply) throws GeneralSecurityException {
        if (!MacVerifier.verifyMac(_serverKey, request.getNonce().getBytes(), reply.getMac().toByteArray())) {
            System.out.println("An error occurred: Unable to validate server response");
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
