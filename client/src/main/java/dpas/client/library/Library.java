package dpas.client.library;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
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

    }

    public void post(PublicKey key, byte[] signature, char[] message, String username, Announcement[] a) {

        List<String> identifiers = new ArrayList<String>();
        for(Announcement announcement: a){
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
    }

    public void postGeneral(PublicKey key, byte[] signature, char[] message, String username, Announcement[] a) {

        List<String> identifiers = new ArrayList<String>();
        for(Announcement announcement: a){
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
    }

    public Announcement[] read(PublicKey publicKey) {
        return null;
    }

    public Announcement[] readGeneral(int number) {
        return null;
    }
}
