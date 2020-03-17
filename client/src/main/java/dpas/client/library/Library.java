package dpas.client.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class Library {

    public ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    public Library(String host, int port) {
        var _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
    }

    public void register(PublicKey publicKey, String username) {
        try {
            _stub.register(Contract.RegisterRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .setUsername(username).build());
        } catch (StatusRuntimeException e) {
            System.out.println("An errror ocurred: " + e.getMessage());
        }

    }

    public void post(PublicKey key, byte[] signature, char[] message, String username, Announcement[] a) {

        try {
            List<String> identifiers = new ArrayList<String>();
            for (Announcement announcement : a) {
                identifiers.add(announcement.getIdentifier());
            }

            Contract.PostRequest postRequest = Contract.PostRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(key.getEncoded()))
                    .setMessage(String.valueOf(message))
                    .setSignature(ByteString.copyFrom(signature))
                    .setUsername(username)
                    .addAllReferences(identifiers)
                    .build();

            _stub.post(postRequest);
        } catch (StatusRuntimeException e) {
            System.out.println("An error ocurred: " + e.getMessage());
        }
    }

    public void postGeneral(PublicKey key, byte[] signature, char[] message, String username, Announcement[] a) {

        try {
            List<String> identifiers = new ArrayList<String>();
            for (Announcement announcement : a) {
                identifiers.add(announcement.getIdentifier());
            }

            Contract.PostRequest postRequest = Contract.PostRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(key.getEncoded()))
                    .setMessage(String.valueOf(message))
                    .setSignature(ByteString.copyFrom(signature))
                    .setUsername(username)
                    .addAllReferences(identifiers)
                    .build();

            _stub.postGeneral(postRequest);
        } catch (StatusRuntimeException e) {
            System.out.println("An error ocurred: " + e.getMessage());
        }
    }


    public Announcement[] read(PublicKey publicKey, String username, int number) {
        try {
            Contract.ReadReply reply =_stub.read(Contract.ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .setUsername(username)
                    .setNumber(number).build());
            return (Announcement[]) reply.getAnnouncementsList().toArray();
        } catch (StatusRuntimeException e) {
            System.out.println("An error ocurred: " + e.getMessage());
            return null;
        }
    }

    public Announcement[] readGeneral (int number) {
        try {
            Contract.ReadReply reply =_stub.readGeneral(Contract.ReadRequest.newBuilder()
                    .setNumber(number).build());
            return (Announcement[]) reply.getAnnouncementsList().toArray();
        } catch (StatusRuntimeException e) {
            System.out.println("An errror ocurred: " + e.getMessage());
            return null;
        }
    }
}
