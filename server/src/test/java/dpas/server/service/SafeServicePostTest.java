package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.bytes.ContractUtils;
import dpas.utils.bytes.CypherUtils;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Base64;

public class SafeServicePostTest {

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private PublicKey _pubKey;
    private PrivateKey _privKey;
    private static final String SESSION_NONCE = "NONCE";
    private static final String MESSAGE = "Message";
    private byte[] _clientMac;
    private Contract.SafePostRequest _request;

    private byte[] _firstSignature;

    private static final int port = 9001;
    private static final String host = "localhost";

    private static ServiceDPASSafeImplNoPersistence _impl;

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;
    private PublicKey _serverPKey;
    private PrivateKey _serverPrivKey;
    private SessionManager _sessionManager;
    private byte[] _message;

    @Before
    public void setup() throws NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException,
            IllegalBlockSizeException, InvalidKeyException, IOException, CommonDomainException {

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(2048);

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();

        _sessionManager = new SessionManager(50000000);

        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();
        _sessionManager.getSessionKeys().put(SESSION_NONCE, new Session(0, _pubKey, SESSION_NONCE, LocalDateTime.now().plusHours(2)));

        _impl = new ServiceDPASSafeImplNoPersistence(_serverPKey, _serverPrivKey, _sessionManager);
        _server = NettyServerBuilder.forPort(port).addService(_impl).build();
        _server.start();

        _firstSignature = Announcement.generateSignature(_privKey, MESSAGE,
                new ArrayList<>(), Base64.getEncoder().encodeToString(_pubKey.getEncoded()));


        //Connect to Server
        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);
        _message = CypherUtils.cipher(MESSAGE.getBytes(), _serverPKey);

        _request = Contract.SafePostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setMessage(ByteString.copyFrom(_message))
                .setSignature(ByteString.copyFrom(_firstSignature))
                .setSeq(3)
                .setSessionNonce(SESSION_NONCE)
                .build();
        byte[] mac = ContractUtils.generateMac(_request, _privKey);

        _request = Contract.SafePostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setMessage(ByteString.copyFrom(_message))
                .setSignature(ByteString.copyFrom(_firstSignature))
                .setMac(ByteString.copyFrom(mac))
                .setSeq(3)
                .setSessionNonce(SESSION_NONCE)
                .build();

        byte[] requestMac = ContractUtils.generateMac(SESSION_NONCE, 1, _privKey);
        var regRequest = Contract.SafeRegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setMac(ByteString.copyFrom(requestMac))
                .setSessionNonce(SESSION_NONCE)
                .setSeq(1)
                .build();
        _stub.safeRegister(regRequest);

    }

    @After
    public void tearDown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void validPost() {
        _stub.safePost(_request);
    }

    @Test
    public void invalidSessionPost() {
        _stub.safePost(_request);
    }


}
