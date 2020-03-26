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
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.net.URISyntaxException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;

public class PostTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    private Server _server;

    private PublicKey _firstPublicKey;
    private PublicKey _secondPublicKey;

    private PrivateKey _secondPrivateKey;

    private byte[] _firstSignature;
    private byte[] _secondSignature;
    private byte[] _bigMessageSignature;

    private String _invalidReference;

    private ManagedChannel _channel;

    private static final String MESSAGE = "Message";
    private static final String SECOND_MESSAGE = "Second Message";
    private static final String INVALID_MESSAGE = StringUtils.repeat("ThisMessageisInvalid", "", 15);

    private static final String host = "localhost";
    private static final int port = 9000;

    @Before
    public void setup() throws IOException, NoSuchAlgorithmException, CommonDomainException, URISyntaxException, InvalidKeySpecException {
        // Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);

        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();
        PrivateKey _firstPrivateKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _secondPublicKey = keyPair.getPublic();
        _secondPrivateKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        PublicKey _serverKey = keyPair.getPublic();

        // References
        _invalidReference = "";


        // Signatures
        _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));

        _secondSignature = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
                new ArrayList<>(), Base64.getEncoder().encodeToString(_secondPublicKey.getEncoded()));


        _bigMessageSignature = Announcement.generateSignature(_firstPrivateKey, INVALID_MESSAGE,
                new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));


        final BindableService impl = new ServiceDPASImpl(_serverKey);
        _server = NettyServerBuilder.forPort(port).addService(impl).build();
        _server.start();

        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

        //Register Users
        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
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
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());
    }

    @Test
    public void twoPostsSuccess() {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setMessage(SECOND_MESSAGE)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }

    @Test
    public void twoPostsValidReference() throws CommonDomainException {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        var firstIdentifier = _stub.read(Contract.ReadRequest
                .newBuilder()
                .setNumber(1)
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build())
                .getAnnouncements(0)
                .getHash();

        byte[] secondSignatureWithRef = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
                Collections.singletonList(firstIdentifier), Base64.getEncoder().encodeToString(_secondPublicKey.getEncoded()));

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
                .setMessage(SECOND_MESSAGE)
                .addReferences(firstIdentifier)
                .setSignature(ByteString.copyFrom(secondSignatureWithRef))
                .build());
    }

    @Test
    public void twoPostsInvalidReference() {
        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_firstSignature))
                .build());

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Reference: reference provided does not exist");

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
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
                .setMessage(MESSAGE)
                .build());
    }

    @Test
    public void postInvalidSignature() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

        _stub.post(Contract.PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_secondSignature))
                .build());
    }
}