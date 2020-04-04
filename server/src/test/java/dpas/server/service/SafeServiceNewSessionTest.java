package dpas.server.service;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
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

public class SafeServiceNewSessionTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static final String SESSION_NONCE = "NONCE";
    private static final String SESSION_NONCE2 = "NONCE2";
    private static final String SESSION_NONCE3 = "NONCE3";
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
    public void setup() throws IOException {
        _sessionManager = new SessionManager(5000);

        _impl = new ServiceDPASSafeImpl(_serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();

        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

    }

    @After
    public void tearDown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validNewSession() throws GeneralSecurityException, IOException {
        var reply = _stub.newSession(ContractGenerator.generateClientHello(_privKey, _pubKey, SESSION_NONCE));
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl.getSessionManager().getSessions().size(), 1);
        assertArrayEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE).getPublicKey().getEncoded(), _pubKey.getEncoded());
    }

    @Test
    public void newSessionWrongClientMac() {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");

        byte[] invalidMac = "ThisIsInvalid".getBytes();
        var request = Contract.ClientHello.newBuilder()
                .setMac(ByteString.copyFrom(invalidMac))
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setSessionNonce(SESSION_NONCE3)
                .build();
        try {
            _stub.newSession(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        } finally {
            assertEquals(_impl.getSessionManager().getSessions().size(), 0);
        }
    }

    @Test
    public void repeatedSessions() throws IOException, GeneralSecurityException {

        var request = ContractGenerator.generateClientHello(_privKey, _pubKey, SESSION_NONCE);
        var reply = _stub.newSession(request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));

        assertEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE).getSessionNonce(), SESSION_NONCE);
        assertArrayEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE).getPublicKey().getEncoded(), _pubKey.getEncoded());
        assertEquals(_impl.getSessionManager().getSessions().size(), 1);

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Session already exists!");
        try {
            _stub.newSession(ContractGenerator.generateClientHello(_privKey, _pubKey, SESSION_NONCE));
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
        finally {
            assertEquals(_impl.getSessionManager().getSessions().size(), 1);
        }
    }


    @Test
    public void twoSessionsSameUser() throws IOException, GeneralSecurityException {
        var reply = _stub.newSession(ContractGenerator.generateClientHello(_privKey, _pubKey, SESSION_NONCE));
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));

        assertEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE).getSessionNonce(), SESSION_NONCE);
        assertArrayEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE).getPublicKey().getEncoded(), _pubKey.getEncoded());
        assertEquals(_impl.getSessionManager().getSessions().size(), 1);


        reply = _stub.newSession(ContractGenerator.generateClientHello(_privKey, _pubKey, SESSION_NONCE2));
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));

        assertEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE2).getSessionNonce(), SESSION_NONCE2);
        assertArrayEquals(_impl.getSessionManager().getSessions().get(SESSION_NONCE2).getPublicKey().getEncoded(), _pubKey.getEncoded());
        assertEquals(_impl.getSessionManager().getSessions().size(), 2);
    }
}
