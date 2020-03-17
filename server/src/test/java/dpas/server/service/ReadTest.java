package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.User;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.apache.commons.lang3.SerializationUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class ReadTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;

    private final static String USER_NAME = "USER";
    private final static String NON_REGISTERED_USER = "USER2";

    private PublicKey _publicKey;
    private User _user;

    private byte[] _signature;
    private byte[] _signature2;

    private final String MESSAGE = "Message to sign";
    private final String SECOND_MESSAGE = "Second message to sign";
    private ArrayList<Announcement> _references = null;

    @Before
    public void setup() throws IOException, NoSuchAlgorithmException, NullPublicKeyException, NullUsernameException,
            NullUserException, NullMessageException, InvalidMessageSizeException, NullSignatureException,
            SignatureException, NullAnnouncementException, InvalidKeyException, InvalidSignatureException,
            InvalidUserException {

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        _publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateKey);
        sign.update(MESSAGE.getBytes());
        _signature = sign.sign();

        Signature sign2 = Signature.getInstance("SHA256withRSA");
        sign2.initSign(privateKey);
        sign.update(SECOND_MESSAGE.getBytes());
        _signature2 = sign.sign();


        _user = new User(USER_NAME, _publicKey);

        Announcement announcement = new Announcement(_signature, _user, MESSAGE, _references);
        _user.getUserBoard().post(announcement);

        final BindableService impl = new ServiceDPASImpl();

        //Start server
        _server = NettyServerBuilder
                .forPort(8091)
                .addService(impl)
                .build();
        _server.start();

        final String host = "localhost";
        final int port = 8091;
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel).withMaxInboundMessageSize(1024 * 1024 * 1024).withMaxOutboundMessageSize(1024 * 1024 * 1024);

        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(_user.getUsername())
                .build());

        _stub.post(Contract.PostRequest.newBuilder()
                .setUsername(USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_signature))
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .build());


        _stub.post(Contract.PostRequest.newBuilder()
                .setUsername(USER_NAME)
                .setMessage(SECOND_MESSAGE)
                .setSignature(ByteString.copyFrom(_signature2))
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .build());


    }

    @After
    public void teardown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readSuccessAllWith0() {

        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
                .setUsername(_user.getUsername())
                .setNumber(0)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
        ArrayList<Announcement> announcements = SerializationUtils.deserialize(reply.getAnnouncements().toByteArray());
        assertEquals(announcements.get(0).getMessage(), MESSAGE);
        assertEquals(announcements.get(0).getUser().getUsername(), USER_NAME);
        assertEquals(announcements.get(0).getUser().getPublicKey(), _publicKey );
        assertEquals(announcements.get(0).get_sequenceNumber(), 0);
        assertArrayEquals(announcements.get(0).getSignature(), _signature);
        assertEquals(announcements.get(0).getReferences(), new ArrayList<>());

        assertEquals(announcements.get(1).getMessage(), SECOND_MESSAGE);
        assertEquals(announcements.get(1).getUser().getUsername(), USER_NAME);
        assertEquals(announcements.get(1).getUser().getPublicKey(), _publicKey );
        assertEquals(announcements.get(1).get_sequenceNumber(), 1);
        assertArrayEquals(announcements.get(1).getSignature(), _signature2);
        assertEquals(announcements.get(1).getReferences(), new ArrayList<>());

    }

    @Test
    public void readSuccessAll() {



        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
                .setUsername(_user.getUsername())
                .setNumber(2)
                .build());


        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
        ArrayList<Announcement> announcements = SerializationUtils.deserialize(reply.getAnnouncements().toByteArray());
        assertEquals(announcements.get(0).getMessage(), MESSAGE);
        assertEquals(announcements.get(0).getUser().getUsername(), USER_NAME);
        assertEquals(announcements.get(0).getUser().getPublicKey(), _publicKey );
        assertEquals(announcements.get(0).get_sequenceNumber(), 0);
        assertArrayEquals(announcements.get(0).getSignature(), _signature);
        assertEquals(announcements.get(0).getReferences(), new ArrayList<>());

        assertEquals(announcements.get(1).getMessage(), SECOND_MESSAGE);
        assertEquals(announcements.get(1).getUser().getUsername(), USER_NAME);
        assertEquals(announcements.get(1).getUser().getPublicKey(), _publicKey );
        assertEquals(announcements.get(1).get_sequenceNumber(), 1);
        assertArrayEquals(announcements.get(1).getSignature(), _signature2);
        assertEquals(announcements.get(1).getReferences(), new ArrayList<>());
    }

    @Test
    public void readSuccess() {


        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(USER_NAME)
                .setNumber(1)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
        ArrayList<Announcement> announcements = SerializationUtils.deserialize(reply.getAnnouncements().toByteArray());
        assertEquals(announcements.get(0).getMessage(), SECOND_MESSAGE);
        assertEquals(announcements.get(0).getUser().getUsername(), USER_NAME);
        assertEquals(announcements.get(0).getUser().getPublicKey(), _publicKey );
        assertEquals(announcements.get(0).get_sequenceNumber(), 1);
        assertArrayEquals(announcements.get(0).getSignature(), _signature2);
        assertEquals(announcements.get(0).getReferences(), new ArrayList<>());

    }

    @Test
    public void readInvalidNumberOfPosts() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Number of Posts");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(USER_NAME)
                .setNumber(-1)
                .build());
    }

    @Test
    public void readNullKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Public Key Provided");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setUsername(USER_NAME)
                .setNumber(0)
                .build());
    }

    @Test
    public void readEmptyKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Public Key Provided");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[0]))
                .setUsername(USER_NAME)
                .setNumber(0)
                .build());
    }

    @Test
    public void readArbitraryKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Public Key Provided");

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[]{12, 2, 12, 5}))
                .setUsername(USER_NAME)
                .setNumber(0)
                .build());
    }

    @Test
    public void readWrongAlgorithmKey() throws NoSuchAlgorithmException {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Public Key Provided");

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setUsername(USER_NAME)
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
                .setUsername(NON_REGISTERED_USER)
                .setNumber(0)
                .build());

    }

}