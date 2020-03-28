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
import java.util.HashSet;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Stream;

import static org.junit.Assert.*;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class ServerConcurrencyTest {

    private ServiceDPASGrpc.ServiceDPASStub _stub;
    private ServiceDPASGrpc.ServiceDPASBlockingStub _blockingStub;
    private Server _server;
    private PublicKey _serverKey;

    private PublicKey _firstPublicKey;


    private PrivateKey _firstPrivateKey;

    private byte[] _firstSignature;


    private ManagedChannel _channel;

    private static final String MESSAGE = "Message";

    private static final String host = "localhost";
    private static final int port = 9000;

    private static final int NUMBER_THREADS = 10;
    private static final int NUMBER_POSTS = NUMBER_THREADS * 50;

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
                new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));


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


    private void postRun() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(NUMBER_POSTS / NUMBER_THREADS);
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
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
                            latch.countDown();
                        }
                    });
        }
        latch.await();
    }

    private void postGeneralRun() throws InterruptedException {
        CountDownLatch latch = new CountDownLatch(NUMBER_POSTS / NUMBER_THREADS);
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
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
                            latch.countDown();
                        }
                    }
            );
        }
        latch.await();
    }

    @Test
    public void concurrencyPostTest() throws CommonDomainException, InterruptedException {
        _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
                new ArrayList<>(), Base64.getEncoder().encodeToString(_firstPublicKey.getEncoded()));
        HashSet<Integer> sequencers = new HashSet<>();
        Thread[] threads = new Thread[NUMBER_THREADS];

        for (int i = 0; i < NUMBER_THREADS; i++) {
            threads[i] = new Thread(() -> {
                try {
                    postRun();
                } catch (InterruptedException e) {
                    fail();
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }

        Contract.ReadReply reply = _blockingStub.read(
                Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
                        .setNumber(NUMBER_POSTS * 2)
                        .build());
        //Check that each announcement was posted correctly
        assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS);

        //Check that each announcement was posted correctly
        for (var announcement : reply.getAnnouncementsList()) {
            assertEquals(announcement.getMessage(), MESSAGE);
            assertArrayEquals(announcement.getPublicKey().toByteArray(), _firstPublicKey.getEncoded());
            assertArrayEquals(announcement.getSignature().toByteArray(), _firstSignature);
            assertTrue(announcement.getSequencer() >= 0);
            assertTrue(announcement.getSequencer() < NUMBER_POSTS);
            assertFalse(sequencers.contains(announcement.getSequencer()));
            sequencers.add(announcement.getSequencer());
        }
    }


    @Test
    public void concurrencyPostGeneralTest() throws CommonDomainException, InterruptedException {
        _firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE, new ArrayList<>(), "DPAS-GENERAL-BOARD");
        HashSet<Integer> sequencers = new HashSet<>();
        Thread[] threads = new Thread[NUMBER_THREADS];

        for (int i = 0; i < NUMBER_THREADS; i++) {
            threads[i] = new Thread(() -> {
                try {
                    postGeneralRun();
                } catch (InterruptedException e) {
                    fail();
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }


        Contract.ReadReply reply = _blockingStub.readGeneral(Contract.ReadRequest.newBuilder()
                .setNumber(NUMBER_POSTS * 2)
                .build());

        assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS);

        //Check that each announcement was posted correctly
        for (var announcement : reply.getAnnouncementsList()) {
            assertEquals(announcement.getMessage(), MESSAGE);
            assertArrayEquals(announcement.getPublicKey().toByteArray(), _firstPublicKey.getEncoded());
            assertArrayEquals(announcement.getSignature().toByteArray(), _firstSignature);
            assertTrue(announcement.getSequencer() >= 0);
            assertTrue(announcement.getSequencer() < NUMBER_POSTS);
            assertFalse(sequencers.contains(announcement.getSequencer()));
            sequencers.add(announcement.getSequencer());
        }
    }
}
