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
import dpas.utils.handler.ErrorGenerator;
import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;

import static org.junit.Assert.*;


public class SafeServicePostGeneralTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _invalidPubKey;
    private static final String MESSAGE = "Message";
    private static final String SESSION_NONCE = "Nonce";

    private static Contract.PostRequest _request;

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
                MESSAGE, 3, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);
    }

    @Before
    public void setup() throws GeneralSecurityException,
            IOException {
        _sessionManager = new SessionManager(50000000);
        _sessionManager.getSessions().put(SESSION_NONCE, new Session(0, _pubKey, SESSION_NONCE, LocalDateTime.now().plusHours(2)));

        _impl = new ServiceDPASSafeImpl(_serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();
        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));

    }

    @After
    public void tearDown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validPost() throws GeneralSecurityException, IOException {
        var reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl._announcements.size(), 1);
    }

    @Test
    public void nonFreshPost() throws GeneralSecurityException, IOException {
        var reply = _stub.safePostGeneral(_request);
        assertEquals(reply.getSessionNonce(), SESSION_NONCE);
        assertEquals(reply.getSeq(), 4);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl._announcements.size(), 1);
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid sequence number");
        try {
            _stub.safePostGeneral(_request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void stealSeqPost() throws GeneralSecurityException, IOException {
        var reply = _stub.safePostGeneral(_request);
        assertEquals(reply.getSessionNonce(), SESSION_NONCE);
        assertEquals(reply.getSeq(), 4);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl._announcements.size(), 1);
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid mac");
        _stub.safePostGeneral(Contract.SafePostRequest.newBuilder(_request).setSeq(5).build());
    }

    @Test
    public void invalidSessionPost() throws GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setSessionNonce(INVALID_SESSION_NONCE).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Session");
        try {
            _stub.safePostGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidSeqPost() throws GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setSeq(7).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid sequence number");
        try {
            _stub.safePostGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidkeyPost() throws GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setPublicKey(ByteString.copyFrom(_invalidPubKey.getEncoded())).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Public Key for request");
        try {
            _stub.safePostGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void nonCipheredPost() throws IOException, GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setMessage(ByteString.copyFrom(MESSAGE.getBytes())).build();
        byte[] mac = MacGenerator.generateMac(request, _privKey);
        request = Contract.SafePostRequest.newBuilder(request).setMac(ByteString.copyFrom(mac)).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        try {
            _stub.safePostGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidMacPost() throws GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setMessage(ByteString.copyFrom(MESSAGE.getBytes())).build();
        request = Contract.SafePostRequest.newBuilder(request).setMac(_request.getMac()).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid mac");
        try {
            _stub.safePostGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void notAMacPost() throws GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setMac(ByteString.copyFrom(new byte[]{12, 4, 56, 21})).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("security values provided");
        try {
            _stub.safePostGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }
}
