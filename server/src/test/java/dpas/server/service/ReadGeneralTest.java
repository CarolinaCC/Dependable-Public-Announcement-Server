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
import java.util.List;

import static dpas.common.domain.GeneralBoard.GENERAL_BOARD_IDENTIFIER;
import static org.junit.Assert.*;

public class ReadGeneralTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private Server _server;

    private ManagedChannel _channel;
    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    private static long _seq;

    private static PublicKey _publicKey;
    private static PrivateKey _privateKey;

    private static byte[] _signature;
    private static final String host = "localhost";
    private static final int port = 9000;


    private static final String MESSAGE = "Message to sign";

    @BeforeClass
    public static void oneTimeSetup() throws CommonDomainException, NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair keyPair = keygen.generateKeyPair();
        _publicKey = keyPair.getPublic();
        _privateKey = keyPair.getPrivate();

        _seq = 1;

        _signature = Announcement.generateSignature(_privateKey, MESSAGE, null, GENERAL_BOARD_IDENTIFIER, _seq);
    }

    @Before
    public void setup() throws IOException {


        // Start Server
        final BindableService impl = new ServiceDPASImpl();
        _server = NettyServerBuilder.forPort(port).addService(impl).build();
        _server.start();

        // Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

        // Register User
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .build());

        // Create Post To Read
        _stub.postGeneral(Contract.Announcement.newBuilder()
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_signature))
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setSeq(_seq)
                .build());
    }

    @After
    public void tearDown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readSuccessAllWith0() {

        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(0).build());

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

        assertEquals(announcementsGRPC.size(), 1);

        assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);
        announcementsGRPC.forEach(a -> assertTrue(ReplyValidator.verifySignature(a)));
    }

    @Test
    public void readSuccessAll() {
        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(3).build());

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

        assertEquals(announcementsGRPC.size(), 1);

        assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);
        announcementsGRPC.forEach(a -> assertTrue(ReplyValidator.verifySignature(a)));
    }

    @Test
    public void readSuccess() {

        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(1).build());

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

        assertEquals(announcementsGRPC.size(), 1);

        assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);
        announcementsGRPC.forEach(a -> assertTrue(ReplyValidator.verifySignature(a)));
    }

    @Test
    public void readInvalidNumberOfPosts() {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid number of posts to read: number cannot be negative");

        _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(-1).build());
    }

}
