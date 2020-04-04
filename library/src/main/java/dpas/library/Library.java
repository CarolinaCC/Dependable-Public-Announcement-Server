package dpas.library;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import com.google.protobuf.ByteString;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.ClientHello;
import dpas.grpc.contract.Contract.ReadReply;
import dpas.grpc.contract.Contract.ReadRequest;
import dpas.grpc.contract.Contract.SafePostRequest;
import dpas.grpc.contract.Contract.SafeRegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import dpas.utils.handler.ErrorGenerator;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;


public class Library {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Map<PublicKey, Session> _sessions;
    private PublicKey _serverKey;
    private ManagedChannel _channel;

    public Library(String host, int port, PublicKey serverKey) {
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _sessions = new HashMap<>();
        _serverKey = serverKey;
    }

    public void finish() {
        _channel.shutdown();
    }

    private void newSession(PublicKey pubKey, PrivateKey privKey) {

        ClientHello request = ClientHello.newBuilder().build();
        try {
            request = ContractGenerator.generateClientHello(privKey, pubKey, UUID.randomUUID().toString());
            var hello = _stub.newSession(request);
            long seq = hello.getSeq() + 1;
            String nonce = hello.getSessionNonce();
            Session session = new Session(nonce, seq);
            _sessions.put(pubKey, session);
        } catch (GeneralSecurityException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getMac().toByteArray(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
            }
        }
    }

    private Session getSession(PublicKey pubKey, PrivateKey privKey) {
        if (!_sessions.containsKey(pubKey)) {
            newSession(pubKey, privKey);
        }
        return _sessions.get(pubKey);
    }

    public void register(PublicKey publicKey, PrivateKey privkey) {
        Session session = null;
        SafeRegisterRequest request = null;
        try {
            session = getSession(publicKey, privkey);
            request = ContractGenerator.generateRegisterRequest(session.getSessionNonce(),
                    session.getSeq(), publicKey, privkey);
            var reply = _stub.safeRegister(request);

            if (!MacVerifier.verifyMac(_serverKey, reply) || session.getSeq() + 1 != reply.getSeq()) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            if (!verifyError(e, request.getMac().toByteArray(), _serverKey)) {
                System.out.println("Unable to authenticate server response");
                return;
            }
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            if (status.getCode().equals(Status.Code.UNAUTHENTICATED)) {
                System.out.println("Creating new session and retrying...");
                newSession(publicKey, privkey);
                register(publicKey, privkey);
            }
        } catch (GeneralSecurityException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        } finally {
            if (session != null) {
                session.updateSeq();
            }
        }
    }

    public void post(PublicKey key, char[] message, Announcement[] a, PrivateKey privateKey) {
        Session session = null;
        SafePostRequest request = SafePostRequest.newBuilder().build();
        try {
            session = getSession(key, privateKey);
            request = ContractGenerator.generatePostRequest(_serverKey, key, privateKey,
                    String.valueOf(message), session.getSessionNonce(),
                    session.getSeq(), Base64.getEncoder().encodeToString(key.getEncoded()), a);
            var reply = _stub.safePost(request);

            if (!MacVerifier.verifyMac(_serverKey, reply) || session.getSeq() + 1 != reply.getSeq()) {
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
                newSession(key, privateKey);
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
        SafePostRequest request = SafePostRequest.newBuilder().build();
        try {
            session = getSession(pubKey, privateKey);
            request = ContractGenerator.generatePostRequest(_serverKey, pubKey, privateKey, String.valueOf(message),
                    session.getSessionNonce(), session.getSeq(), GENERAL_BOARD_IDENTIFIER, a);

            var reply = _stub.safePostGeneral(request);

            if (!MacVerifier.verifyMac(_serverKey, reply) || session.getSeq() + 1 != reply.getSeq()) {
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
                newSession(pubKey, privateKey);
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
