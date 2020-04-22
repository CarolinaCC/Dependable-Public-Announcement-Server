package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.security.SecurityManager;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.auth.MacGenerator;
import dpas.utils.auth.MacVerifier;
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

    private static PublicKey _pubKey2;
    private static PrivateKey _privKey2;
    private static PublicKey _invalidPubKey;
    private static PrivateKey _invalidPrivKey;
    private static final String MESSAGE = "Message";
    private static final String SESSION_NONCE = "Nonce";

    private static Contract.Announcement _request;
    private static Contract.Announcement _request2;
    private static Contract.Announcement _secondUserRequest;
    private static Contract.Announcement _invalidSeqRequest;
    private static Contract.Announcement _invalidPubKeyRequest;
    private static Contract.Announcement _invalidIdentifierRequest;


    private static final int port = 9001;
    private static final String host = "localhost";

    private static ServiceDPASSafeImpl _impl;

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;
    private static PublicKey _serverPKey;
    private static PrivateKey _serverPrivKey;
    private SecurityManager _securityManager;

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
        _pubKey2 = keyPair.getPublic();
        _privKey2 = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _invalidPubKey = keyPair.getPublic();
        _invalidPrivKey = keyPair.getPrivate();

        _request = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, 1, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _invalidIdentifierRequest = Contract.Announcement.newBuilder(_request).setIdentifier("").build();

        _request2 = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, 2, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _secondUserRequest = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey2, _privKey2,
                MESSAGE, 1, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _invalidSeqRequest = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, 1 + 10, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _invalidPubKeyRequest = ContractGenerator.generateAnnouncement(_serverPKey, _invalidPubKey, _invalidPrivKey,
                MESSAGE, 1, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

    }

    @Before
    public void setup() throws GeneralSecurityException,
            IOException {
        _securityManager = new SecurityManager();

        _impl = new ServiceDPASSafeImpl(_serverPrivKey, _securityManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();
        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));
        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey2, _privKey2));
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
    public void validVariousPost() throws GeneralSecurityException {
        var reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
        assertEquals(_impl._announcements.size(), 1);
        reply = _stub.postGeneral(_request2);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request2));
        assertEquals(_impl._announcements.size(), 2);
        reply = _stub.postGeneral(_secondUserRequest);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _secondUserRequest));
        assertEquals(_impl._announcements.size(), 3);
    }


    @Test
    public void repeatedPost() throws GeneralSecurityException {
        var reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
        assertEquals(_impl._announcements.size(), 1);
        reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
        assertEquals(_impl._announcements.size(), 1);
    }

    @Test
    public void postInvalidIdentifier() throws GeneralSecurityException, IOException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid identifier");
        try {
            _stub.postGeneral(_invalidIdentifierRequest);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _invalidIdentifierRequest.getSignature().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }


    @Test
    public void stealSeqPost() throws GeneralSecurityException, IOException {
        var reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
        assertEquals(_impl._announcements.size(), 1);
        _stub.postGeneral(_request);

        reply = _stub.postGeneral(_request);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, _request));
        assertEquals(_impl._announcements.size(), 1);
        _stub.postGeneral(_request);
    }

    @Test
    public void postFutureRequest() throws GeneralSecurityException, IOException {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid seq");
        try {
            _stub.post(_invalidSeqRequest);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _invalidSeqRequest.getSignature().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.UNAUTHENTICATED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }


    @Test
    public void invalidkeyPost() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid User provided: Does Not Exist");
        try {
            _stub.postGeneral(_invalidPubKeyRequest);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), _invalidPubKeyRequest.getSignature().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void nonCipheredPost() throws IOException, GeneralSecurityException {
        var request = Contract.Announcement.newBuilder(_request).setMessage(MESSAGE).build();
        byte[] mac = MacGenerator.generateMac(request, _privKey);
        request = Contract.Announcement.newBuilder(request).setSignature(ByteString.copyFrom(mac)).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        try {
            _stub.postGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getSignature().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidMacPost() {
        var request = Contract.Announcement.newBuilder(_request).setSignature(_invalidPubKeyRequest.getSignature()).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Signature Could not be verified");
        try {
            _stub.postGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getSignature().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void notAMacPost() throws GeneralSecurityException {
        var request = Contract.Announcement.newBuilder(_request).setSignature(ByteString.copyFrom(new byte[]{12, 4, 56, 21})).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Security Values Provided");
        try {
            _stub.postGeneral(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getSignature().toByteArray());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }
}
