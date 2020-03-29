package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.bytes.ContractUtils;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.Base64;

import static org.junit.Assert.*;

public class ServiceSafeImplTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private PublicKey _pubKey;
    private PrivateKey _privKey;
    private static final String SESSION_NONCE = "NONCE";
    private static final String SESSION_NONCE2 = "NONCE2";
    private static final String SESSION_NONCE3 = "NONCE3";
    private byte[] _clientMac;

    private static final int port = 9001;
    private static final String host = "localhost";

    private static ServiceDPASSafeImplNoPersistence _impl;

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;
    private PublicKey _serverPKey;
    private PrivateKey _serverPrivKey;
    private SessionManager _sessionManager;

    @Before
    public void setup() throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException, IOException {

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        KeyPair keyPair = keygen.generateKeyPair();
        KeyPair serverPair = keygen.generateKeyPair();

        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();
        _sessionManager = new SessionManager(5000);

        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();
        _sessionManager.getSessionKeys().put(SESSION_NONCE, new Session(0, _pubKey, SESSION_NONCE, LocalDateTime.now().plusHours(1)));

        Cipher cipherServer = Cipher.getInstance("RSA");
        cipherServer.init(Cipher.ENCRYPT_MODE, _privKey);

        String content = SESSION_NONCE2 + Base64.getEncoder().encodeToString(_pubKey.getEncoded());

        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] encodedHashClient = digest.digest(content.getBytes());
        _clientMac = cipherServer.doFinal(encodedHashClient);

        _impl = new ServiceDPASSafeImplNoPersistence(_serverPKey, _serverPrivKey, _sessionManager);
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
    public void validNewSession() {

        _stub.newSession(Contract.ClientHello.newBuilder().setMac(ByteString.copyFrom(_clientMac)).setPublicKey(ByteString.copyFrom(_pubKey.getEncoded())).setSessionNonce(SESSION_NONCE2).build());
        assertEquals(_impl.getSessionManager().getSessionKeys().get(SESSION_NONCE2).getSessionNonce(), SESSION_NONCE2);
        assertArrayEquals(_impl.getSessionManager().getSessionKeys().get(SESSION_NONCE2).getPublicKey().getEncoded(), _pubKey.getEncoded());
    }

    @Test
    public void newSessionWrongClientMac() {

        exception.expect(StatusRuntimeException.class);
        exception.expectMessage("Invalid Client HMAC");

        byte[] invalidMac = "ThisIsInvalid".getBytes();
        _stub.newSession(Contract.ClientHello.newBuilder().setMac(ByteString.copyFrom(invalidMac)).setPublicKey(ByteString.copyFrom(_pubKey.getEncoded())).setSessionNonce(SESSION_NONCE3).build());

    }

    @Test
    public void validRegister() throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] requestMac = ContractUtils.generateMac(SESSION_NONCE, 1, _privKey );
        Contract.SafeRegisterReply regReply = _stub.safeRegister(Contract.SafeRegisterRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                        .setMac(ByteString.copyFrom(requestMac))
                        .setSessionNonce(SESSION_NONCE)
                        .setSeq(1)
                        .build());

        byte[] mac = regReply.getMac().toByteArray();

        assertEquals(_impl.getSessionManager().getSessionKeys().get(SESSION_NONCE).getSessionNonce(), SESSION_NONCE);
        assertEquals(_impl.getSessionManager().getSessionKeys().get(SESSION_NONCE).getSequenceNumber(), 2);
        assertArrayEquals( ContractUtils.generateMac(SESSION_NONCE, 2, _serverPrivKey), mac);
    }


    @Test
    public void invalidSessionNonceRegister() throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] requestMAC = ContractUtils.generateMac(SESSION_NONCE, 1, _privKey );
        _stub.safeRegister(Contract.SafeRegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setSessionNonce("invalido")
                .setSeq(1)
                .setMac(ByteString.copyFrom(requestMAC))
                .build());

    }

    @Test
    public void invalidSeqNonceRegister() throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        byte[] requestMAC = ContractUtils.generateMac(SESSION_NONCE, 1, _privKey );
        _stub.safeRegister(Contract.SafeRegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setSessionNonce("invalido")
                .setSeq(1)
                .setMac(ByteString.copyFrom(requestMAC))
                .build());
    }

    @Test
    public void invalidMacNonceRegister() throws BadPaddingException, NoSuchAlgorithmException, IOException, IllegalBlockSizeException, NoSuchPaddingException, InvalidKeyException {
        //_stub.newSession(Contract.ClientHello.newBuilder().setMac(ByteString.copyFrom(_clientMac)).setPublicKey(ByteString.copyFrom(_pubKey.getEncoded())).setSessionNonce(SESSION_NONCE).build());

        byte[] requestMAC = ContractUtils.generateMac("ola", 1, _privKey );
        _stub.safeRegister(Contract.SafeRegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setSessionNonce(SESSION_NONCE)
                .setSeq(1)
                .setMac(ByteString.copyFrom(requestMAC))
                .build());
    }

}
