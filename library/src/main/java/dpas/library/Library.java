package dpas.library;

import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.link.PerfectStub;
import dpas.utils.link.QuorumStub;
import dpas.utils.link.RegisterStub;
import io.grpc.ManagedChannel;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.channel.nio.NioEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.socket.nio.NioSocketChannel;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

public class Library {

    private final RegisterStub stub;

    public Library(String host, int port, PublicKey[] serverKey, int numFaults) {
        List<PerfectStub> stubs = new ArrayList<>();
        for (int i = 0; i < 3 * numFaults + 1; i++) {
            //One thread for each channel
            var executor = Executors.newSingleThreadExecutor(); //One thread for each stub
            var eventGroup = new NioEventLoopGroup(1); //One thread for each channel
            ManagedChannel channel = NettyChannelBuilder
                    .forAddress(host, port + i + 1)
                    .usePlaintext()
                    .channelType(NioSocketChannel.class)
                    .eventLoopGroup(eventGroup)
                    .executor(executor)
                    .build();
            channel.resetConnectBackoff(); //Try to reconnect immediately after crash
            var stub = ServiceDPASGrpc.newStub(channel);
            PerfectStub pStub = new PerfectStub(stub, serverKey[i]);
            stubs.add(pStub);
        }
        stub = new RegisterStub(new QuorumStub(stubs, numFaults));
    }

    public void register(PublicKey publicKey, PrivateKey privkey) {
        try {
            stub.register(publicKey, privkey);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void post(PublicKey key, char[] message, Announcement[] a, PrivateKey privateKey) {
        try {
            stub.post(key, privateKey, String.valueOf(message), a);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public void postGeneral(PublicKey pubKey, char[] message, Announcement[] a, PrivateKey privateKey) {
        try {
            stub.postGeneral(pubKey, privateKey, String.valueOf(message), a);
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    public Announcement[] read(PublicKey publicKey, int number) {
        try {
            return stub.read(publicKey, number);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return new Announcement[0];
        }
    }

    public Announcement[] readGeneral(int number) {
        try {
            return stub.readGeneral(number);
        } catch (Exception e) {
            System.out.println(e.getMessage());
            return new Announcement[0];
        }
    }
}
