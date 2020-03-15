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
    private PublicKey _firstPublicKey;
    private PublicKey _secondPublicKey;
    private ManagedChannel _channel;

    private final static String FIRST_USER_NAME = "USER";
    private final static String SECOND_USER_NAME = "USER2";


    @Before
    public void setup() throws IOException, NoSuchAlgorithmException {

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();

        keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        _secondPublicKey = keyPair.getPublic();

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
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_OK);
    }

    @Test
    public void registerTwoUsers() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_OK);

        reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_OK);
    }

    @Test
    public void registerNullUsername() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_NULL_USERNAME);
    }
    @Test
    public void registerNullKey() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_NULL_PUBLICKEY);
    }

    @Test
    public void registerEmptyKey() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[0]))
                .setUsername(FIRST_USER_NAME)
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_NULL_PUBLICKEY);
    }

    @Test
    public void registerArbitraryKey() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[] {12, 2, 12, 5}))
                .setUsername(FIRST_USER_NAME)
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_NULL_PUBLICKEY);
    }

    @Test
    public void registerWrongAlgorithmKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_NULL_PUBLICKEY);
    }

    @Test
    public void registerRepeatedUser() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_OK);

        reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_REPEATED_USER);
    }

    @Test
    public void registerRepeatedPublicKeyUser() {
        Contract.RegisterReply reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_OK);

        reply = _stub.register(Contract.RegisterRequest.newBuilder()
                .setUsername(SECOND_USER_NAME)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
        assertEquals(reply.getStatus(), Contract.RegisterStatus.REGISTERSTATUS_REPEATED_USER);
    }
}
