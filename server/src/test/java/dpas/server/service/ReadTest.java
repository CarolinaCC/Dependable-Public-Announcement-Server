package dpas.server.service;

import dpas.common.domain.Announcement;
import dpas.common.domain.User;
import dpas.common.domain.exception.*;

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
import java.security.*;
import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class ReadTest {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;

    private final static String USER_NAME = "USER";

    private PublicKey _publicKey;
    private User _user;
    private int _numberToRead;
    private byte[] _signature;
    private final String MESSAGE = "Message to sign";
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

        _user = new User(USER_NAME, _publicKey);
        _numberToRead = 0;

        Announcement announcement = new Announcement(_signature, _user, MESSAGE, _references);
        _user.getUserBoard().post(announcement);

        final BindableService impl =  new ServiceDPASImpl();

        //Start server
        _server = NettyServerBuilder
                .forPort(8091)
                .addService(impl)
                .build();
        _server.start();

        final String host = "localhost";
        final int port = 8091;
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel).withMaxInboundMessageSize(1024*1024*1024).withMaxOutboundMessageSize(1024 * 1024 * 1024);

        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(_user.getUsername())
                .build());
    }

    @After
    public void teardown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readSuccessAll() {

        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
                .setUsername(_user.getUsername())
                .setNumber(_numberToRead)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
    }

   @Test
    public void readSuccess() {

        int numberToRead = 1;

        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(USER_NAME)
                .setNumber(numberToRead)
                .build());
        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
    }

    @Test
    public void readInvalidNumberOfPosts() {
        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                .setUsername(USER_NAME)
                .setNumber(-1)
                .build());
        assertEquals(reply.getStatus(), Contract.ReadStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION);
    }

    @Test
    public void readNullKey() {
        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setUsername(USER_NAME)
                .setNumber(_numberToRead)
                .build());
        assertEquals(reply.getStatus(), Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION);
    }

    @Test
    public void readEmptyKey() {
        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[0]))
                .setUsername(USER_NAME)
                .setNumber(_numberToRead)
                .build());
        assertEquals(reply.getStatus(), Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION);
    }

    @Test
    public void readArbitraryKey() {
        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[] {12, 2, 12, 5}))
                .setUsername(USER_NAME)
                .setNumber(_numberToRead)
                .build());
        assertEquals(reply.getStatus(), Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION);
    }

    @Test
    public void readWrongAlgorithmKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();

        Contract.ReadReply reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setUsername(USER_NAME)
                .setNumber(_numberToRead)
                .build());
        assertEquals(reply.getStatus(), Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION);
    }

}