package dpas.server.service;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.ArrayUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import dpas.utils.handler.ErrorGenerator;
import io.grpc.ManagedChannel;
import io.grpc.Metadata;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class SafeServiceReadGeneralTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static Contract.ReadRequest _readRequest;

    private static final int port = 9001;
    private static final String host = "localhost";

    private static ServiceDPASSafeImpl _impl;
    private static long _seq;
    private static long _secondSeq;
    private static String _nonce = "Nonce";
    private static String _secondNonce = "Nonce";

    private static ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private static Server _server;
    private static ManagedChannel _channel;

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _secondPubKey;
    private static byte[] _signature;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;

    private static final String MESSAGE = "Message to sign";
    private static final String SECOND_MESSAGE = "Second message to sign";

    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, IOException, CommonDomainException {

        _secondNonce = UUID.randomUUID().toString();
        _seq = new SecureRandom().nextLong();
        _secondSeq = new SecureRandom().nextLong();
        UUID.randomUUID().toString();
        UUID.randomUUID().toString();

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();
        _nonce = UUID.randomUUID().toString();
        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        keyPair.getPublic();

        keyPair = keygen.generateKeyPair();
        _secondPubKey = keyPair.getPublic();
        keyPair.getPrivate();


        //Signatures
        _signature = Announcement.generateSignature(_privKey, MESSAGE, null, GeneralBoard.GENERAL_BOARD_IDENTIFIER);
        Announcement.generateSignature(_privKey, SECOND_MESSAGE, null, Base64.getEncoder().encodeToString(_pubKey.getEncoded()));

    }

    @Before
    public void setup() throws IOException, GeneralSecurityException, CommonDomainException {

        SessionManager _sessionManager = new SessionManager(50000000);
        _sessionManager.getSessions().put(_nonce, new Session(_seq, _pubKey, _nonce, LocalDateTime.now().plusHours(2)));
        _sessionManager.getSessions().put(_secondNonce, new Session(_secondSeq, _secondPubKey, _secondNonce, LocalDateTime.now().plusHours(2)));

        _impl = new ServiceDPASSafeImpl(_serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();

        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);


        _stub.safeRegister(ContractGenerator.generateRegisterRequest(_nonce, _seq + 1, _pubKey, _privKey));

        // Posts to Read
        _stub.safePostGeneral(ContractGenerator.generatePostRequest(_serverPKey, _pubKey, _privKey, MESSAGE, _nonce, _seq + 3, GeneralBoard.GENERAL_BOARD_IDENTIFIER,
                null));
    }

    @After
    public void teardown() {

        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void readValid() throws GeneralSecurityException {
        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(1)
                .setNonce("Nonce")
                .build();

        var reply = _stub.readGeneral(request);

        List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();
        assertEquals(announcementsGRPC.size(), 1);
        assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
        assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
        assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _pubKey.getEncoded());
        assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);

        assertTrue(MacVerifier.verifyMac(_serverPKey, request.getNonce().getBytes(), reply.getMac().toByteArray()));
    }


    @Test
    public void readGeneralNegativeNumber() {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("number cannot be negative");

        _readRequest = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(-1)
                .setNonce("Nonce2")
                .build();

        try {
            _stub.read(_readRequest);

        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), ArrayUtils.addAll(_readRequest.getNonce().getBytes()));
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

}


