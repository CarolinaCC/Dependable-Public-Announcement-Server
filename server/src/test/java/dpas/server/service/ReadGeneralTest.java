package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.GeneratedMessage;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.*;
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

import static org.junit.Assert.assertEquals;

public class ReadGeneralTest {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;
    private byte[] _signature;
    private User _user;
    private final String MESSAGE = "Message to sign";
    private final String USER_NAME = "USER";

    private GeneralBoard _generalBoard;
    private int _numberToRead;

    @Before
    public void setup() throws IOException, InvalidKeyException, NoSuchAlgorithmException, NullAnnouncementException,
            NullMessageException, SignatureException, InvalidSignatureException, NullSignatureException,
            NullUserException, InvalidMessageSizeException, NullPublicKeyException, NullUsernameException {

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        Signature sign = Signature.getInstance("SHA256withRSA");
        sign.initSign(privateKey);
        sign.update(MESSAGE.getBytes());
        _signature = sign.sign();

        _user = new User(USER_NAME, publicKey);
        Announcement announcement = new Announcement(_signature, _user, MESSAGE, null);

        _generalBoard = new GeneralBoard();
        _generalBoard.post(announcement);
        _numberToRead = 0;

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
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
    }

    @After
    public void tearDown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readSuccessAllWith0() {

        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder()
                .setNumber(_numberToRead)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
    }

    @Test
    public void readSuccessAll() {

        _numberToRead = 3; //Number bigger than the ammount of posts

        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder()
                .setNumber(_numberToRead)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
    }

    @Test
    public void readSuccess() {

        _numberToRead = 1;

        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder()
                .setNumber(_numberToRead)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.READ_OK);
    }


    @Test
    public void readInvalidNumberOfPosts() {

        _numberToRead = -1;

        Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder()
                .setNumber(_numberToRead)
                .build());

        assertEquals(reply.getStatus(), Contract.ReadStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION);
    }

}

