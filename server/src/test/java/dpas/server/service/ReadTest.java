package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.auth.ReplyValidator;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.*;

public class ReadTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;

    private static PublicKey _publicKey;
    private static PrivateKey _privateKey;

    private static long _seq;

    private static byte[] _signature;
    private static byte[] _signature2;


    private static final String MESSAGE = "Message to sign";
    private static final String SECOND_MESSAGE = "Second message to sign";

    private static final String host = "localhost";
    private static final int port = 9000;

    @BeforeClass
    public static void oneTimeSetup() throws NoSuchAlgorithmException, CommonDomainException {
        // Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair keyPair = keygen.generateKeyPair();
        _publicKey = keyPair.getPublic();
        _privateKey = keyPair.getPrivate();

        _seq = 1;

        //Signatures
        _signature = Announcement.generateSignature(_privateKey, MESSAGE, null, Base64.getEncoder().encodeToString(_publicKey.getEncoded()), _seq);
        _signature2 = Announcement.generateSignature(_privateKey, SECOND_MESSAGE, null, Base64.getEncoder().encodeToString(_publicKey.getEncoded()), _seq + 1);

    }


    @Before
    public void setup() throws IOException {

        //Start Server
        final BindableService impl = new ServiceDPASImpl();
        _server = NettyServerBuilder.forPort(port).addService(impl).build();
        _server.start();

        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

        // Register User
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .build());

        // Posts to Read
        _stub.post(Contract.Announcement.newBuilder()
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_signature))
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setSeq(_seq)
                .build());
        _stub.post(Contract.Announcement.newBuilder()
                .setMessage(SECOND_MESSAGE)
                .setSignature(ByteString.copyFrom(_signature2))
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setSeq(_seq + 1)
                .build());
    }

    @After
    public void teardown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readSuccessAllWith0() {

        Contract.ReadReply reply = _stub.read(
                Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                        .setNumber(0)
                        .build());

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

        assertEquals(announcementsGRPC.size(), 2);

        assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);

        assertEquals(announcementsGRPC.get(1).getMessage(), SECOND_MESSAGE);
        assertEquals(announcementsGRPC.get(1).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(1).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(1).getSignature().toByteArray(), _signature2);
        announcementsGRPC.forEach(a -> assertTrue(ReplyValidator.verifySignature(a,
                _publicKey, Base64.getEncoder().encodeToString(_publicKey.getEncoded()))));
    }

    @Test
    public void readSuccessAll() {

        Contract.ReadReply reply = _stub.read(
                Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                        .setNumber(2)
                        .build());

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

        assertEquals(announcementsGRPC.size(), 2);

        assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);

        assertEquals(announcementsGRPC.get(1).getMessage(), SECOND_MESSAGE);
        assertEquals(announcementsGRPC.get(1).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(1).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(1).getSignature().toByteArray(), _signature2);
        announcementsGRPC.forEach(a -> assertTrue(ReplyValidator.verifySignature(a,
                _publicKey, Base64.getEncoder().encodeToString(_publicKey.getEncoded()))));
    }

    @Test
    public void readSuccess() {

        var reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setNumber(1)
                .build());

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

        assertEquals(announcementsGRPC.size(), 1);

        assertEquals(announcementsGRPC.get(0).getMessage(), SECOND_MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature2);
        announcementsGRPC.forEach(a -> assertTrue(ReplyValidator.verifySignature(a,
                _publicKey, Base64.getEncoder().encodeToString(_publicKey.getEncoded()))));
    }

    @Test
    public void readInvalidNumberOfPosts() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid number of posts to read: number cannot be negative");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setNumber(-1)
                .build());
    }

    @Test
    public void readNullKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");

        _stub.read(Contract.ReadRequest.newBuilder().setNumber(0).build());
    }

    @Test
    public void readEmptyKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[0]))
                .setNumber(0)
                .build());
    }

    @Test
    public void readArbitraryKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: invalid key format");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[]{12, 2, 12, 5}))
                .setNumber(0)
                .build());
    }

    @Test
    public void readWrongAlgorithmKey() throws NoSuchAlgorithmException {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Invalid RSA public key");

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setNumber(0)
                .build());
    }

    @Test
    public void readUserNotRegistered() throws NoSuchAlgorithmException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: User with public key does not exist");

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setNumber(0)
                .build());

    }

}