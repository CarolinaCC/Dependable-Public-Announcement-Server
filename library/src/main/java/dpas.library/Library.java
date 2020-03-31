package dpas.library;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.PostRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;


public class Library {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Map<PublicKey, Session> _sessions;
    private PublicKey _serverKey;

    public Library(String host, int port, PublicKey serverKey) {
        var _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _sessions = new HashMap<>();
        _serverKey = serverKey;
    }

    private void newSession(PublicKey pubKey, PrivateKey privKey) {
        try {
            var hello = _stub.newSession(ContractGenerator.generateClientHello(privKey, pubKey, UUID.randomUUID().toString()));
            long seq = hello.getSeq();
            String nonce = hello.getSessionNonce();
            Session session = new Session(nonce, seq);
            _sessions.put(pubKey, session);
        } catch (GeneralSecurityException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        }
    }

    private Session checkSession(PublicKey pubKey, PrivateKey privKey) {
        if (!_sessions.containsKey(pubKey)) {
            newSession(pubKey, privKey);
        }
        return _sessions.get(pubKey);
    }

    public void register(PublicKey publicKey, PrivateKey privkey) {
        try {
            var session = checkSession(publicKey, privkey);
            var reply = _stub.safeRegister(ContractGenerator.generateRegisterRequest(session.getSessionNonce(), session.getSeq(), publicKey, privkey));
            if (!MacVerifier.verifyMac(_serverKey, reply)) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            if (status.getDescription().equals("Session is expired")) {
                System.out.println("Creating new session and retrying...");
                newSession(publicKey, privkey);
                register(publicKey, privkey);
            }
        } catch (GeneralSecurityException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        }
    }

    public void post(PublicKey key, char[] message, Announcement[] a, PrivateKey privateKey) {
        try {
            Session session = checkSession(key, privateKey);
            var reply = _stub.safePost(ContractGenerator.generatePostRequest(_serverKey, key, privateKey, String.valueOf(message) , session.getSessionNonce(), session.getSeq(), Base64.getEncoder().encodeToString(key.getEncoded()), a));

            if (! MacVerifier.verifyMac(_serverKey, reply)) {
                System.out.println("An error occurred: Unable to validate server response.");
            }
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            if (status.getDescription().equals("Session is expired")) {
                System.out.println("Creating a new session and retrying...");
                newSession(key, privateKey);
                post(key, message, a, privateKey);
            }
        }  catch (GeneralSecurityException | CommonDomainException| IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
        }
    }

    public void postGeneral(PublicKey pubKey, char[] message, Announcement[] a, PrivateKey privateKey) {
        try {
            var sessions = checkSession(pubKey, privateKey);
            var safePostGeneralReply = _stub.safePostGeneral(ContractGenerator.generatePostRequest(_serverKey, pubKey,
                    privateKey, String.valueOf(message), sessions.getSessionNonce(), sessions.getSeq(),
                    GENERAL_BOARD_IDENTIFIER, a));

            if (!MacVerifier.verifyMac(_serverKey, safePostGeneralReply)) {
                System.out.println("An error occurred: Unable to validate server response");
            }
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
            if (status.getDescription().equals("Session is expired")) {
                System.out.println("Creating new session and retrying...");
                newSession(pubKey, privateKey);
                register(pubKey, privateKey);
            }
        } catch (GeneralSecurityException | CommonDomainException | IOException e) {
            //Should never happen
            System.out.println("An error has occurred that has forced the application to shutdown");
            System.exit(1);
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

    private PostRequest createPostRequest(String boardIdentifier, PublicKey key, char[] message, Announcement[] a,
                                          PrivateKey privateKey) throws CommonDomainException {

        List<String> references = a == null ? new ArrayList<>()
                : Stream.of(a).map(Announcement::getHash).collect(Collectors.toList());

        byte[] signature = dpas.common.domain.Announcement.generateSignature(privateKey, String.valueOf(message),
                references, boardIdentifier);

        return PostRequest.newBuilder()
                .setMessage(String.copyValueOf(message))
                .setPublicKey(ByteString.copyFrom(key.getEncoded()))
                .addAllReferences(references)
                .setSignature(ByteString.copyFrom(signature))
                .build();
    }

    private PostRequest createPostGeneralRequest(PublicKey key, char[] message, Announcement[] a,
                                                 PrivateKey privateKey) throws CommonDomainException {
        return createPostRequest(GENERAL_BOARD_IDENTIFIER, key, message, a, privateKey);
    }

    private PostRequest createPostRequest(PublicKey key, char[] message, Announcement[] a,
                                          PrivateKey privateKey) throws CommonDomainException {
        return createPostRequest(Base64.getEncoder().encodeToString(key.getEncoded()), key, message, a, privateKey);
    }


}
