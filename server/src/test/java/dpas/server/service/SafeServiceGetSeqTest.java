package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.security.SecurityManager;
import dpas.utils.CipherUtils;
import dpas.utils.ContractGenerator;
import dpas.utils.ErrorGenerator;
import dpas.utils.MacVerifier;
import io.grpc.*;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.UUID;

import static org.junit.Assert.*;

public class SafeServiceGetSeqTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();


    private static final int port = 9001;
    private static final String host = "localhost";

    private static long _seq;

    private static ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private static Server _server;
    private static ManagedChannel _channel;

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _pubKey2;
    private static PrivateKey _privKey2;
    private static PublicKey _pubKey3;
    private static PrivateKey _privKey3;


    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;

    private static final String MESSAGE = "Message to sign";

    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, IOException, CommonDomainException {

        _seq = 1;

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

        _pubKey3 = keyPair.getPublic();
        _privKey3 = keyPair.getPrivate();
    }

    @Before
    public void setup() throws IOException, GeneralSecurityException, CommonDomainException {

        SecurityManager _securityManager = new SecurityManager();
        ServiceDPASSafeImpl _impl = new ServiceDPASSafeImpl(_serverPrivKey, _securityManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();

        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);


        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));
        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey2, _privKey2));

        _stub.post(ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey, MESSAGE, _seq, CipherUtils.keyToString(_pubKey),
                null));
        _stub.post(ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey, MESSAGE, _seq + 1, CipherUtils.keyToString(_pubKey),
                null));
        _stub.postGeneral(ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey, MESSAGE, _seq + 2, GeneralBoard.GENERAL_BOARD_IDENTIFIER,
                null));
    }

    @After
    public void teardown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validGetSeq() throws GeneralSecurityException, IOException {
        var request = Contract.GetSeqRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = _stub.getSeq(request);
        assertEquals(reply.getSeq(), 2);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, request));
    }

    @Test
    public void validGetSeqNoPosts() throws GeneralSecurityException, IOException {
        var request = Contract.GetSeqRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey2.getEncoded()))
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = _stub.getSeq(request);
        assertEquals(reply.getSeq(), 0);
        assertTrue(MacVerifier.verifyMac(_serverPKey, reply, request));
    }

    @Test
    public void noUserSeq() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("User with that public key does not exist");

        var request = Contract.GetSeqRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey3.getEncoded()))
                .setNonce(UUID.randomUUID().toString())
                .build();
        try {
            _stub.getSeq(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getNonce().getBytes());
            assertEquals(e.getStatus().getCode(), Status.INVALID_ARGUMENT.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }

    @Test
    public void invalidKeyGetSeq() {
        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid security values provided");

        var request = Contract.GetSeqRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(new byte[]{1, 2, 2, 3, 4}))
                .setNonce(UUID.randomUUID().toString())
                .build();
        try {
            _stub.getSeq(request);
        } catch (StatusRuntimeException e) {
            Metadata data = e.getTrailers();
            assertArrayEquals(data.get(ErrorGenerator.contentKey), request.getNonce().getBytes());
            assertEquals(e.getStatus().getCode(), Status.CANCELLED.getCode());
            assertTrue(MacVerifier.verifyMac(_serverPKey, e));
            throw e;
        }
    }
}




