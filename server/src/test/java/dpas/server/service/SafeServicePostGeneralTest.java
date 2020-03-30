package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.ContractGenerator;
import dpas.utils.MacGenerator;
import dpas.utils.MacVerifier;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class SafeServicePostGeneralTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _invalidPubKey;
    private static final String SESSION_NONCE = "NONCE";
    private static final String INVALID_SESSION_NONCE = "NONCE2";
    private static final String MESSAGE = "Message";

    private static Contract.SafePostRequest _request;

    private static final int port = 9001;
    private static final String host = "localhost";

    private static ServiceDPASSafeImpl _impl;

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;
    private static PublicKey _serverPKey;
    private static PrivateKey _serverPrivKey;
    private SessionManager _sessionManager;

    @BeforeClass
    public static void onTimeSetup() throws GeneralSecurityException, IOException, CommonDomainException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();


        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();


        keyPair = keygen.generateKeyPair();
        _invalidPubKey = keyPair.getPublic();


        _request = ContractGenerator.generatePostRequest(_serverPKey, _pubKey, _privKey,
                MESSAGE, SESSION_NONCE, 3, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);
    }

    @Before
    public void setup() throws GeneralSecurityException,
            IOException {
        _sessionManager = new SessionManager(50000000);
        _sessionManager.getSessions().put(SESSION_NONCE, new Session(0, _pubKey, SESSION_NONCE, LocalDateTime.now().plusHours(2)));

        _impl = new ServiceDPASSafeImpl(_serverPKey, _serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();
        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _stub.safeRegister(ContractGenerator.generateRegisterRequest(SESSION_NONCE, 1, _pubKey, _privKey));

    }

    @After
    public void tearDown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validPost() throws GeneralSecurityException, IOException {
        var reply = _stub.safePostGeneral(_request);
        assertEquals(reply.getSessionNonce(), SESSION_NONCE);
        assertEquals(reply.getSeq(), 4);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl._announcements.size(), 1);
    }

    @Test
    public void invalidSessionPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setSessionNonce(INVALID_SESSION_NONCE).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Session");
        _stub.safePostGeneral(request);
    }

    @Test
    public void invalidSeqPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setSeq(7).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid sequence number");
        _stub.safePostGeneral(request);
    }

    @Test
    public void invalidkeyPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setPublicKey(ByteString.copyFrom(_invalidPubKey.getEncoded())).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Public Key for request");
        _stub.safePostGeneral(request);
    }

    @Test
    public void nonCipheredPost() throws IOException, GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setMessage(ByteString.copyFrom(MESSAGE.getBytes())).build();
        byte[] mac = MacGenerator.generateMac(request, _privKey);
        request = Contract.SafePostRequest.newBuilder(request).setMac(ByteString.copyFrom(mac)).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        _stub.safePostGeneral(request);
    }

    @Test
    public void invalidMacPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setMessage(ByteString.copyFrom(MESSAGE.getBytes())).build();
        request = Contract.SafePostRequest.newBuilder(request).setMac(_request.getMac()).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid mac");
        _stub.safePostGeneral(request);
    }

    @Test
    public void notAMacPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setMac(ByteString.copyFrom(new byte[]{12, 4, 56, 21})).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("security values provided");
        _stub.safePostGeneral(request);
    }
}
