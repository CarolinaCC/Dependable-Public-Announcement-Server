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
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.List;

public class PostTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    private Server _server;
    private PublicKey _firstPublicKey;
    private PublicKey _secondPublicKey;
    private byte[] _firstSignature;
    private byte[] _secondSignature;
    private byte[] _bigMessageSignature;

    private String _invalidReference;


    private ManagedChannel _channel;

    private final static String FIRST_USER_NAME = "USER";
    private final static String SECOND_USER_NAME = "USER2";

    private static final String MESSAGE = "Message";
    private static final String SECOND_MESSAGE = "Second Message";
    private static final String INVALID_MESSAGE = "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid" +
            "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid";


    @Before
    public void setup() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();

        // generate first signature
        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update(MESSAGE.getBytes());
        _firstSignature = sign.sign();

        // second key pair
        keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        _secondPublicKey = keyPair.getPublic();

        // Generate second signature
        sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update(SECOND_MESSAGE.getBytes());
        _secondSignature = sign.sign();


        // third key pair
        keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        keyPair = keygen.generateKeyPair();
        PublicKey _thirdPublicKey = keyPair.getPublic();

        // Generate signature for too big message
        sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(keyPair.getPrivate());
        sign.update(INVALID_MESSAGE.getBytes());
        _bigMessageSignature = sign.sign();


        _invalidReference = "";

        final BindableService impl = new ServiceDPASImpl();

        //Start server
        _server = NettyServerBuilder
                .forPort(9000)
                .addService(impl)
                .build();
        _server.start();

        final String host = "localhost";
        final int port = 9000;
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

        // create first user
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .build());

        // create second user
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setUsername(SECOND_USER_NAME)
                .build());
    }

    @After
    public void teardown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void postSuccess() {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());
    }

    @Test
    public void twoPostsSuccess() {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setUsername(SECOND_USER_NAME)
                .setMessage(SECOND_MESSAGE)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }

    @Test
    public void twoPostsValidReference() {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        Contract.ReadReply readReply = _stub.read(Contract.ReadRequest.newBuilder()
                .setNumber(1)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .build());

        List<Contract.Announcement> announcementsGRPC = readReply.getAnnouncementsList();

        String validReference = announcementsGRPC.get(0).getIdentifier();

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setUsername(SECOND_USER_NAME)
                .setMessage(SECOND_MESSAGE)
                .addReferences(validReference)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }

    @Test
    public void twoPostsInvalidReference() {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Reference: reference provided does not exist");

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setUsername(SECOND_USER_NAME)
                .setMessage(SECOND_MESSAGE)
                .addReferences(_invalidReference)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());

    }


    @Test
    public void postNullPublicKey() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");

        _stub.post(Contract.PostRequest.newBuilder()
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());
    }

    @Test
    public void postInvalidMessageSize() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Message");

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(INVALID_MESSAGE)
                .setSignature(ByteString.copyFrom(_bigMessageSignature))
                .build());
    }


    @Test
    public void postNullSignature() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .build());

    }

    @Test
    public void postInvalidSignature() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setUsername(FIRST_USER_NAME)
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }

}