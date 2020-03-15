package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import static org.junit.Assert.assertEquals;

public class RegisterTest {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private PublicKey _publicKey;
    private ManagedChannel _channel;

    private final static String USER_NAME = "USER";

    @Before
    public void setup() throws IOException, NoSuchAlgorithmException {

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        _publicKey = keyPair.getPublic();

        final BindableService impl =  new ServiceDPASImpl();

        //Start server
        _server = NettyServerBuilder
                .forPort(8090)
                .addService(impl)
                .build();
        _server.start();

        final String host = "localhost";
        final int port = 8090;
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

    }

    @After
    public void teardown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void registerSuccess() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(USER_NAME)
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_OK);
    }
}
