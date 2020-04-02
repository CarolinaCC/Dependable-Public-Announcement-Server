package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.MacVerifier;
import dpas.utils.handler.ErrorGenerator;
import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.rules.ExpectedException;


import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;

public class SafeServiceReadTest {

    public ExpectedException exception = ExpectedException.none();

    private static Contract.ReadRequest _readRequest;

    private static final int port = 9000;
    private static final String host = "localhost";

    private static ServiceDPASSafeImpl _impl;
    private static long _seq;
    private static long _secondSeq;
    private static int _number;
    private static String _nonce = "Nonce";
    private static String _secondNonce = "Nonce";

    private static ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private static Server _server;
    private static ManagedChannel _channel;

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _secondPubKey;
    private static PrivateKey _secondPrivKey;


    private static byte[] _signature;
    private static byte[] _signature2;

    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;

    private static final String MESSAGE = "Message to sign";
    private static final String SECOND_MESSAGE = "Second message to sign";

    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, IOException, CommonDomainException {

        _secondNonce = UUID.randomUUID().toString();
        _seq = new SecureRandom().nextLong();
        _secondSeq = new SecureRandom().nextLong();

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();
        _nonce = UUID.randomUUID().toString();
        _number = 0;

        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _secondPubKey = keyPair.getPublic();
        _secondPrivKey = keyPair.getPrivate();


        //Signatures
        _signature = Announcement.generateSignature(_privKey, MESSAGE, null, Base64.getEncoder().encodeToString(_pubKey.getEncoded()));
        _signature2 = Announcement.generateSignature(_privKey, SECOND_MESSAGE, null, Base64.getEncoder().encodeToString(_pubKey.getEncoded()));

    }

    @Before
    public void setup() throws IOException {

        SessionManager _sessionManager = new SessionManager(50000000);
        _sessionManager.getSessions().put(_nonce, new Session(_seq, _pubKey, _nonce, LocalDateTime.now().plusHours(2)));
        _sessionManager.getSessions().put(_secondNonce, new Session(_secondSeq, _secondPubKey, _secondNonce, LocalDateTime.now().plusHours(2)));


        _impl = new ServiceDPASSafeImpl(_serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();

        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);


        _stub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .build());

        // Posts to Read
        _stub.post(Contract.PostRequest.newBuilder()
                .setMessage(MESSAGE)
                .setSignature(ByteString.copyFrom(_signature))
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .build());
        _stub.post(Contract.PostRequest.newBuilder()
                .setMessage(SECOND_MESSAGE)
                .setSignature(ByteString.copyFrom(_signature2))
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .build());
    }

    @After
    public void teardown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readValid() {
            var reply = _stub.read(Contract.ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                    .setNumber(1)
                    .build());

            List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();
            assertEquals(announcementsGRPC.size(), 1);
            assertEquals(announcementsGRPC.get(0).getMessage(), SECOND_MESSAGE);
            assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
            assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _pubKey.getEncoded());
            assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature2);
    }

    @Test
    public void readWrongPublicKey() throws NoSuchAlgorithmException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("User with public key does not exist");

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        KeyPair serverPair = keygen.generateKeyPair();
        PublicKey pubKey = serverPair.getPublic();
        Contract.ReadReply reply = Contract.ReadReply.newBuilder().build();

        try { reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setNumber(1)
                .build());

        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), reply.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }

    }

    @Test
    public void readWrongMac() throws NoSuchAlgorithmException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("");

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        KeyPair serverPair = keygen.generateKeyPair();
        PublicKey pubKey = serverPair.getPublic();

        Contract.ReadReply reply = Contract.ReadReply.newBuilder().build();

        try { reply = _stub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(1)
                .build());

        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), reply.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(pubKey, e));
            throw e;
        }

    }



}




