package dpas.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import io.grpc.ManagedChannel;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;


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
        try {
            var hello = _stub.newSession(ContractGenerator.generateClientHello(privKey, pubKey, UUID.randomUUID().toString()));
            long seq = hello.getSeq() + 1;
            String nonce = hello.getSessionNonce();
            Session session = new Session(nonce, seq);
            _sessions.put(pubKey, session);
        } catch (GeneralSecurityException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
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
        try {
            session = getSession(publicKey, privkey);
            var reply = _stub.safeRegister(ContractGenerator.generateRegisterRequest(session.getSessionNonce(),
                    session.getSeq(), publicKey, privkey));

            if (!MacVerifier.verifyMac(_serverKey, reply) || session.getSeq() + 1 != reply.getSeq()) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
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
        try {
            session = getSession(key, privateKey);
            var reply = _stub.safePost(ContractGenerator.generatePostRequest(_serverKey, key, privateKey,
                    String.valueOf(message), session.getSessionNonce(),
                    session.getSeq(), Base64.getEncoder().encodeToString(key.getEncoded()), a));

            if (!MacVerifier.verifyMac(_serverKey, reply) || session.getSeq() + 1 != reply.getSeq()) {
                System.out.println("An error occurred: Unable to validate server response.");
            }
        } catch (StatusRuntimeException e) {
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
        try {
            session = getSession(pubKey, privateKey);
            var reply = _stub.safePostGeneral(ContractGenerator.generatePostRequest(_serverKey, pubKey,
                    privateKey, String.valueOf(message), session.getSessionNonce(), session.getSeq(),
                    GENERAL_BOARD_IDENTIFIER, a));

            if (!MacVerifier.verifyMac(_serverKey, reply) || session.getSeq() + 1 != reply.getSeq()) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
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

    public Announcement[] read(PublicKey publicKey, int number) {
        try {
            var reply = _stub.read(Contract.ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .setNumber(number)
                    .build());
            var a = new Announcement[reply.getAnnouncementsCount()];
            reply.getAnnouncementsList().toArray(a);
            return a;
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            return new Announcement[0];
        }
    }

    public Announcement[] readGeneral(int number) {
        try {
            Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(number).build());
            var a = new Announcement[reply.getAnnouncementsCount()];
            reply.getAnnouncementsList().toArray(a);
            return a;
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            return new Announcement[0];
        }
    }
}
