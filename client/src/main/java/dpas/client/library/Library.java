package dpas.client.library;

import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.security.PublicKey;

public class Library {

    public ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    public Library(String host, int port) {
        var _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
    }

    public void register(PublicKey publicKey, String username) {

    }

    public void post(PublicKey key, char[] message, Announcement[] a) {

    }

    public void postGeneral(PublicKey key, char[] message, Announcement[] a) {

    }

    public Announcement[] read(PublicKey publicKey) {
        return null;
    }

    public Announcement[] readGeneral(int number) {
        return null;
    }
}
