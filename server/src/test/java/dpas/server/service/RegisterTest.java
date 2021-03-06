package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

public class RegisterTest {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private static PublicKey _firstPublicKey;
    private static PublicKey _secondPublicKey;
    private static PublicKey _publicDSAKey;
    private ManagedChannel _channel;

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final String host = "localhost";
    private static final int port = 9000;

    @BeforeClass
    public static void oneTimeSetup() throws NoSuchAlgorithmException {
        //Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();

        keyPair = keygen.generateKeyPair();
        _secondPublicKey = keyPair.getPublic();

        keygen = KeyPairGenerator.getInstance("DSA");
        keygen.initialize(2048);
        keyPair = keygen.generateKeyPair();
        _publicDSAKey = keyPair.getPublic();

    }

    @Before
    public void setup() throws IOException {
        // Start server
        final BindableService impl = new ServiceDPASImpl();
        _server = NettyServerBuilder.forPort(port).addService(impl).build();
        _server.start();

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
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
    }

    @Test
    public void registerTwoUsers() {
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());

        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .build());
    }

    @Test
    public void registerNullKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");
        _stub.register(Contract.RegisterRequest.newBuilder().build());
    }

    @Test
    public void registerEmptyKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[0]))
                .build());
    }

    @Test
    public void registerArbitraryKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: invalid key format");
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[]{12, 2, 12, 5}))
                .build());
    }

    @Test
    public void registerWrongAlgorithmKey() throws NoSuchAlgorithmException {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Invalid RSA public key");

        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicDSAKey.getEncoded()))
                .build());
    }
}
