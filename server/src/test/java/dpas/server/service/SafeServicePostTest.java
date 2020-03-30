package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.ContractGenerator;
import dpas.utils.CypherUtils;
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
import java.util.UUID;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class SafeServicePostTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;

    private static PublicKey _invalidPubKey;
    private static String _nonce ;
    private static long seq;
    private static String _invalidNonce;

    private static final String MESSAGE = "Message";
    private static final String LONGMESSAGE = "A".repeat(255);

    private static Contract.SafePostRequest _request;
    private static Contract.SafePostRequest _longRequest;

    private static final int port = 9001;
    private static final String host = "localhost";

    private static ServiceDPASSafeImpl _impl;

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;


    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, IOException, CommonDomainException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        _nonce = UUID.randomUUID().toString();
        _invalidNonce = UUID.randomUUID().toString();
        seq = new SecureRandom().nextLong();

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();


        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();


        keyPair = keygen.generateKeyPair();
        _invalidPubKey = keyPair.getPublic();

        _request = ContractGenerator.generatePostRequest(_serverPKey, _pubKey, _privKey,
                MESSAGE, _nonce, seq + 3, CypherUtils.keyToString(_pubKey), null);

        _longRequest = ContractGenerator.generatePostRequest(_serverPKey, _pubKey, _privKey,
                LONGMESSAGE, _nonce, seq + 3, CypherUtils.keyToString(_pubKey), null);

    }

    @Before
    public void setup() throws GeneralSecurityException,
            IOException, CommonDomainException {

        SessionManager _sessionManager = new SessionManager(50000000);

        _sessionManager.getSessions().put(_nonce, new Session(seq, _pubKey, _nonce, LocalDateTime.now().plusHours(2)));

        _impl = new ServiceDPASSafeImpl(_serverPKey, _serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();


        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);




        _stub.safeRegister(ContractGenerator.generateRegisterRequest(_nonce, seq + 1, _pubKey, _privKey));

    }

    @After
    public void tearDown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validPost() throws GeneralSecurityException, IOException {
        var reply = _stub.safePost(_request);
        assertEquals(reply.getSessionNonce(), _nonce);
        assertEquals(reply.getSeq(), seq + 4);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl._announcements.size(), 1);
    }

    @Test
    public void validLongPost() throws GeneralSecurityException, IOException {
        var reply = _stub.safePost(_longRequest);
        assertEquals(reply.getSessionNonce(), _nonce);
        assertEquals(reply.getSeq(), seq + 4);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply));
        assertEquals(_impl._announcements.size(), 1);
    }

    @Test
    public void invalidSessionPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setSessionNonce(_invalidNonce).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Session");
        _stub.safePost(request);
    }

    @Test
    public void invalidSeqPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setSeq(7).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid sequence number");
        _stub.safePost(request);
    }

    @Test
    public void invalidkeyPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setPublicKey(ByteString.copyFrom(_invalidPubKey.getEncoded())).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Public Key for request");
        _stub.safePost(request);
    }

    @Test
    public void nonCipheredPost() throws IOException, GeneralSecurityException {
        var request = Contract.SafePostRequest.newBuilder(_request).setMessage(ByteString.copyFrom(MESSAGE.getBytes())).build();
        byte[] mac = MacGenerator.generateMac(request, _privKey);
        request = Contract.SafePostRequest.newBuilder(request).setMac(ByteString.copyFrom(mac)).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");
        _stub.safePost(request);
    }

    @Test
    public void invalidMacPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setMessage(ByteString.copyFrom(MESSAGE.getBytes())).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid mac");
        _stub.safePost(request);
    }

    @Test
    public void notAMacPost() {
        var request = Contract.SafePostRequest.newBuilder(_request).setMac(ByteString.copyFrom(new byte[] {12, 4, 56, 21})).build();
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("security values provided");
        _stub.safePost(request);
    }
}
