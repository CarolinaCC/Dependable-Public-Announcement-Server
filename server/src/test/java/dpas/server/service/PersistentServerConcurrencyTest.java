package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
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

import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class PersistentServerConcurrencyTest {

    private ServiceDPASGrpc.ServiceDPASStub _stub;
    private ServiceDPASGrpc.ServiceDPASBlockingStub _blockingStub;
    private Server _server;
    private PublicKey _serverKey;

    private PublicKey _firstPublicKey;


    private PrivateKey _firstPrivateKey;

    private PersistenceManager _manager;


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

    public PersistentServerConcurrencyTest() {
    }

    @Before
    public void setup() throws NoSuchAlgorithmException, CommonDomainException, IOException, URISyntaxException {

        // Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);

        KeyPair keyPair = keygen.generateKeyPair();
        _firstPublicKey = keyPair.getPublic();
        _firstPrivateKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _serverKey = keyPair.getPublic();


        URL res = getClass().getClassLoader().getResource("no_operations_3.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();
        _manager = new PersistenceManager(path, _serverKey);
        _manager.clearSaveFile();
        // Signatures
        _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));


        final BindableService impl = new ServiceDPASPersistentImpl(_manager, _serverKey);
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
    public void concurrencyPostTest() throws CommonDomainException, InterruptedException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        final AtomicInteger t = new AtomicInteger(50);

        for (int i = 0; i < 50; i++) {

            // Signatures
            _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                    new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));
            _stub.post(Contract.PostRequest.newBuilder()
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
            if (t.get() != 0) {
                t.wait();
            }
        }
        Contract.ReadReply reply = _blockingStub.read(
                Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                        .setNumber(100)
                        .build());
        assertEquals(reply.getAnnouncementsCount(), 50);

        //reload save
        var impl = _manager.load();
        assertEquals(impl.getAnnouncements().size(), 50);
    }


    @Test
    public void concurrencyPostGeneralTest() throws CommonDomainException, InterruptedException, NoSuchAlgorithmException, IOException, InvalidKeySpecException {
        final AtomicInteger t = new AtomicInteger(50);

        for (int i = 0; i < 50; i++) {
            _firstIdentifier = UUID.randomUUID().toString();
            // Signatures
            _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                    new ArrayList<>(), "DPAS-GENERAL-BOARD");
            _stub.postGeneral(Contract.PostRequest.newBuilder()
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
            if (t.get() != 0) {
                t.wait();
            }
        }
        Contract.ReadReply reply = _blockingStub.readGeneral(
                Contract.ReadRequest.newBuilder()
                        .setNumber(100)
                        .build());
        assertEquals(reply.getAnnouncementsCount(), 50);

        //reload save
        var impl = _manager.load();
        assertEquals(impl.getAnnouncements().size(), 50);
    }
}
