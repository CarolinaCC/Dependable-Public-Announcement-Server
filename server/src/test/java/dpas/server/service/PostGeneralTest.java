package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.apache.commons.lang3.StringUtils;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.Collections;
import java.util.HashSet;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;

public class PostGeneralTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    private Server _server;

    private static PublicKey _firstPublicKey;
    private static PublicKey _secondPublicKey;

    private static PrivateKey _firstPrivateKey;
    private static PrivateKey _secondPrivateKey;


    private static byte[] _firstSignature;
    private static byte[] _secondSignature;
    private static byte[] _secondSignatureWithRef;
    private static byte[] _bigMessageSignature;

    private ManagedChannel _channel;

    private static final String MESSAGE = "Message";
    private static final String SECOND_MESSAGE = "Second Message";
    private static final String INVALID_MESSAGE = StringUtils.repeat("ThisMessageisInvalid", "", 15);

    @BeforeClass
    public static void oneTimeSetup() throws NoSuchAlgorithmException, CommonDomainException {

        // KeyPairs
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();
        _firstPrivateKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _secondPublicKey = keyPair.getPublic();
        _secondPrivateKey = keyPair.getPrivate();


        //Signatures
        _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                new HashSet<>(), GENERAL_BOARD_IDENTIFIER);

        _secondSignature = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
                new HashSet<>(), GENERAL_BOARD_IDENTIFIER);

        Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
                new HashSet<>(), GENERAL_BOARD_IDENTIFIER);


        _bigMessageSignature = Announcement.generateSignature(_firstPrivateKey, INVALID_MESSAGE,
                new HashSet<>(), GENERAL_BOARD_IDENTIFIER);

    }

    @Before
    public void setup() throws IOException {

        // Start server
        final BindableService impl = new ServiceDPASImpl();
        _server = NettyServerBuilder.forPort(9000).addService(impl).build();
        _server.start();

        // Connect to server
        final String host = "localhost";
        final int port = 9000;
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

        // Register Users
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded())).build());
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .build());

    }

    @After
    public void teardown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void postSuccess() {
        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());
    }

    @Test
    public void twoPostsSuccess() {
        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setMessage(SECOND_MESSAGE).setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }

    @Test
    public void twoPostsWithReference() throws CommonDomainException {
        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        var firstIdentifier = _stub.readGeneral(Contract.ReadRequest
                .newBuilder()
                .setNumber(1)
                .build())
                .getAnnouncements(0)
                .getHash();

        _secondSignatureWithRef = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
                Collections.singleton(firstIdentifier), GENERAL_BOARD_IDENTIFIER);


        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setMessage(SECOND_MESSAGE)
                .addReferences(firstIdentifier)
                .setSignature(ByteString.copyFrom(_secondSignatureWithRef))
                .build());
    }


    @Test
    public void postNullPublicKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Missing key encoding");

        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());
    }

    @Test
    public void postInvalidMessageSize() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Message Length provided: over 255 characters");

        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(INVALID_MESSAGE)
                .setSignature(ByteString.copyFrom(_bigMessageSignature))
                .build());
    }

    @Test
    public void postNullSignature() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .build());
    }

    @Test
    public void postInvalidSignature() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Signature: Signature Could not be verified");

        _stub.postGeneral(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }

}
