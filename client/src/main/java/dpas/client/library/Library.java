package dpas.client.library;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

import java.security.PublicKey;

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

    public void post(PublicKey key, char[] message, Announcement[] a) {
    }

    public void postGeneral(PublicKey key, char[] message, Announcement[] a) {

    }

    public Announcement[] read(PublicKey publicKey, String username, int number) {
        try {
            Contract.ReadReply reply =_stub.read(Contract.ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                    .setUsername(username)
                    .setNumber(number).build());
            return (Announcement[]) reply.getAnnouncementsList().toArray();
        } catch (StatusRuntimeException e) {
            System.out.println("An errror ocurred: " + e.getMessage());
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
