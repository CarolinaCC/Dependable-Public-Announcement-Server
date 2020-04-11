package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.SessionManager;
import dpas.utils.*;
import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;

import static org.junit.Assert.*;


public class SafeServicePostGeneralTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _invalidPubKey;
    private static PrivateKey _invalidPrivKey;
    private static final String MESSAGE = "Message";
    private static final String SESSION_NONCE = "Nonce";

    private static Contract.PostRequest _request;
    private static Contract.PostRequest _invalidSeqRequest;
    private static Contract.PostRequest _invalidPubKeyRequest;

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
        _invalidPrivKey = keyPair.getPrivate();

        _request = ContractGenerator.generatePostRequest(_serverPKey, _pubKey, _privKey,
                MESSAGE, 1, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _invalidSeqRequest = ContractGenerator.generatePostRequest(_serverPKey, _pubKey, _privKey,
                MESSAGE, 1 + 10, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _invalidPubKeyRequest = ContractGenerator.generatePostRequest(_serverPKey, _invalidPubKey, _invalidPrivKey,
                MESSAGE, 1, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

    }

    @Before
    public void setup() throws GeneralSecurityException,
            IOException {
        _sessionManager = new SessionManager();

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
    public void validPost() throws GeneralSecurityException {
        var reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
        assertEquals(_impl._announcements.size(), 1);
    }

    @Test
    public void stealSeqPost() throws GeneralSecurityException, IOException {

        try{
            var reply = _stub.postGeneral(_request);
            assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
            assertEquals(_impl._announcements.size(), 1);
            exception.expect(StatusRuntimeException.class);
            exception.expectMessage("Invalid Seq provided");
            _stub.postGeneral(_request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }


    @Test
    public void invalidSeqPost() throws GeneralSecurityException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Seq provided");
        try {
            _stub.postGeneral(_invalidSeqRequest);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _invalidSeqRequest.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidkeyPost() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("User with that public key does not exist");
        try {
            _stub.postGeneral(_invalidPubKeyRequest);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _invalidPubKeyRequest.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void nonCipheredPost() throws IOException, GeneralSecurityException {
        var request = Contract.PostRequest.newBuilder(_request).setMessage(MESSAGE).build();
        byte[] mac = MacGenerator.generateMac(request, _privKey);
        request = Contract.PostRequest.newBuilder(request).setMac(ByteString.copyFrom(mac)).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        try {
            _stub.postGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidMacPost() {
        var request = Contract.PostRequest.newBuilder(_request).setMessage(MESSAGE).build();
        request = Contract.PostRequest.newBuilder(request).setMac(_request.getMac()).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid mac");
        try {
            _stub.postGeneral(request);
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
        var request = Contract.PostRequest.newBuilder(_request).setMac(ByteString.copyFrom(new byte[]{12, 4, 56, 21})).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("security values provided");
        try {
            _stub.postGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getMac().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }
}
