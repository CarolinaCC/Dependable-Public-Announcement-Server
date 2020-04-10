package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.SessionManager;
import dpas.utils.ContractGenerator;
import dpas.utils.MacVerifier;
import dpas.utils.handler.ErrorGenerator;
import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;

import static org.junit.Assert.*;

public class SafeServiceGoodbyeTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static final String SESSION_NONCE = "NONCE";

    private long _seq;

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
    public static void oneTimeSetup() throws NoSuchAlgorithmException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        KeyPair keyPair = keygen.generateKeyPair();
        KeyPair serverPair = keygen.generateKeyPair();

        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();


        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();
    }

    @Before
    public void setup() throws GeneralSecurityException,
            IOException {

        _sessionManager = new SessionManager(15000);
        _impl = new ServiceDPASSafeImpl(_serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();

        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _seq = _stub.newSession(ContractGenerator.generateClientHello(_privKey, _pubKey, SESSION_NONCE)).getSeq();
    }

    @After
    public void tearDown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validGoodbye() throws GeneralSecurityException, IOException {
        _stub.goodbye(ContractGenerator.generateGoodbyeRequest(_privKey, SESSION_NONCE, _seq + 1));
        assertEquals(_impl.getSessionManager().getSessions().size(), 0);
    }

    @Test
    public void goodbyeInvalidSeq() throws GeneralSecurityException, IOException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid sequence number");
        var request = ContractGenerator.generateGoodbyeRequest(_privKey, SESSION_NONCE, _seq + 3);
        try {
            _stub.goodbye(request);
            assertEquals(_impl.getSessionManager().getSessions().size(), 1);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void goodbyeInvalidNonce() throws GeneralSecurityException, IOException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Session");
        var request = ContractGenerator.generateGoodbyeRequest(_privKey, "Invalid", _seq + 1);
        try {
            _stub.goodbye(request);
            assertEquals(_impl.getSessionManager().getSessions().size(), 1);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void goodbyeInvalidMacKey() throws GeneralSecurityException, IOException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        KeyPair keyPair = keygen.generateKeyPair();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        var request = ContractGenerator.generateGoodbyeRequest(keyPair.getPrivate(), SESSION_NONCE, _seq + 1);
        try {
            _stub.goodbye(request);
            assertEquals(_impl.getSessionManager().getSessions().size(), 1);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }

    }

    @Test
    public void invalicMac() throws GeneralSecurityException, IOException {
        var req = ContractGenerator.generateGoodbyeRequest(_privKey, SESSION_NONCE, _seq + 1);
        req = Contract.GoodByeRequest.newBuilder(req).setMac(ByteString.copyFrom(new byte[]{23, 21, 23})).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        try {
            _stub.goodbye(req);
            assertEquals(_impl.getSessionManager().getSessions().size(), 1);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), req.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

}
