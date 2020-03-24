package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class ServerConcurrencyTest {

    private ServiceDPASGrpc.ServiceDPASStub _stub;
    private ServiceDPASGrpc.ServiceDPASBlockingStub _blockingStub;
    private Server _server;
    private PublicKey _serverKey;

    private PublicKey _firstPublicKey;


    private PrivateKey _firstPrivateKey;


    private String _firstIdentifier;
    private String _secondIdentifier;

    private byte[] _firstSignature;


    private ManagedChannel _channel;

    private static final String MESSAGE = "Message";
    private static final String SECOND_MESSAGE = "Second Message";

    private static final String host = "localhost";
    private static final int port = 9000;

    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[10][0];
    }

    public ServerConcurrencyTest() {
    }

    @Before
    public void setup() throws NoSuchAlgorithmException, CommonDomainException, IOException {


        // Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);

        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();
        _firstPrivateKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _serverKey = keyPair.getPublic();

        // Signatures
        _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                _firstIdentifier, new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));


        final BindableService impl = new ServiceDPASImpl(_serverKey);
        _server = NettyServerBuilder.forPort(port).addService(impl).build();
        _server.start();

        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newStub(_channel);
        _blockingStub = ServiceDPASGrpc.newBlockingStub(_channel);

        //Register Users
        _blockingStub.register(Contract.RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                .build());
    }

    @After
    public void teardown() {
        _server.shutdown();
        _channel.shutdown();
    }

    @Test
    public void concurrencyPostTest() throws CommonDomainException, InterruptedException {
        final AtomicInteger t = new AtomicInteger(50);

        for (int i = 0; i < 50; i++) {
            _firstIdentifier = UUID.randomUUID().toString();
            // Signatures
            _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                    _firstIdentifier, new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));
            _stub.post(Contract.PostRequest.newBuilder()
                            .setIdentifier(_firstIdentifier)
                            .setMessage(MESSAGE)
                            .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                            .setSignature(ByteString.copyFrom(_firstSignature))
                            .build(),
                    new StreamObserver<>() {
                        @Override
                        public void onNext(Empty value) {

                        }

                        @Override
                        public void onError(Throwable t) {

                        }

                        @Override
                        public void onCompleted() {
                            synchronized (this) {
                                int k = t.decrementAndGet();
                                if (k == 0) {
                                    synchronized (t) {
                                        t.notify();
                                    }
                                }
                            }
                        }
                    });
        }
        synchronized (t) {
            t.wait();
        }
        Contract.ReadReply reply = _blockingStub.read(
                Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                        .setNumber(100)
                        .build());
        assertEquals(reply.getAnnouncementsCount(), 50);
    }


    @Test
    public void concurrencyPostGeneralTest() throws CommonDomainException, InterruptedException {
        final AtomicInteger t = new AtomicInteger(50);

        for (int i = 0; i < 50; i++) {
            _firstIdentifier = UUID.randomUUID().toString();
            // Signatures
            _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                    _firstIdentifier, new ArrayList<>(), "DPAS-GENERAL-BOARD");
            _stub.postGeneral(Contract.PostRequest.newBuilder()
                            .setIdentifier(_firstIdentifier)
                            .setMessage(MESSAGE)
                            .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                            .setSignature(ByteString.copyFrom(_firstSignature))
                            .build(),
                    new StreamObserver<>() {
                        @Override
                        public void onNext(Empty value) {

                        }

                        @Override
                        public void onError(Throwable t) {

                        }

                        @Override
                        public void onCompleted() {
                            synchronized (this) {
                                int k = t.decrementAndGet();
                                if (k == 0) {
                                    synchronized (t) {
                                        t.notify();
                                    }
                                }
                            }
                        }
                    });
        }
        synchronized (t) {
            t.wait();
        }
        Contract.ReadReply reply = _blockingStub.readGeneral(
                Contract.ReadRequest.newBuilder()
                        .setNumber(100)
                        .build());
        assertEquals(reply.getAnnouncementsCount(), 50);
    }
}
