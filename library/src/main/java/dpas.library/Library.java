package dpas.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.PostRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;

public class Library {

    public ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    public Library(String host, int port) {
        var _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
    }

    public void register(PublicKey publicKey) {
        try {
            _stub.register(Contract.RegisterRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .build());
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        }
    }

    public void post(PublicKey key, char[] message, Announcement[] a, PrivateKey privateKey) {
        try {
            _stub.post(createPostRequest(key, message, a, privateKey));
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        } catch (CommonDomainException e) {
            //Should never happen
            System.out.println("Could not create signature from values provided");
        }
    }

    public void postGeneral(PublicKey key, char[] message, Announcement[] a, PrivateKey privateKey) {
        try {
            _stub.postGeneral(createPostGeneralRequest(key, message, a, privateKey));
        } catch (StatusRuntimeException e) {
            Status status = e.getStatus();
            System.out.println("An error occurred: " + status.getDescription());
        } catch (CommonDomainException e) {
            System.out.println("Could not create signature from values provided");
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
