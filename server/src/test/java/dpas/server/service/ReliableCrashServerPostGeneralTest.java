package dpas.server.service;

import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.link.PerfectStub;
import dpas.utils.link.QuorumStub;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.channel.nio.NioEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.socket.nio.NioSocketChannel;
import io.grpc.stub.StreamObserver;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class ReliableCrashServerPostGeneralTest {
    private PerfectStub[] _stubs;

    private Server[] _servers;
    private ServiceDPASReliableImpl[] _impls;
    private QuorumStub _stub;

    private static PublicKey[] _serverPubKey;
    private static PrivateKey[] _serverPrivKey;

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;

    private ManagedChannel[] _channels;

    private ExecutorService[] _executors;

    private static Contract.Announcement _request;
    private static Contract.Announcement _request1;
    private static Contract.Announcement _request2;
    private static Contract.Announcement _request3;
    private static Contract.Announcement _request4;

    private static Contract.Announcement[] _requests;

    private static long _seq = 0;

    private static final String MESSAGE = "MESSAGE";
    private static final String MESSAGE1 = "MESSAGE1";
    private static final String MESSAGE2 = "MESSAGE2";
    private static final String MESSAGE3 = "MESSAGE3";
    private static final String MESSAGE4 = "MESSAGE4";

    private static final String host = "localhost";
    private static final int port = 9000;


    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[5][0];
    }

    public ReliableCrashServerPostGeneralTest() {
    }

    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, CommonDomainException {
        // Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        _serverPubKey = new PublicKey[4];
        _serverPrivKey = new PrivateKey[4];
        for (int i = 0; i < 4; i++) {
            KeyPair keyPair = keygen.generateKeyPair();
            _serverPubKey[i] = keyPair.getPublic();
            _serverPrivKey[i] = keyPair.getPrivate();
        }
        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();
        _request = ContractGenerator.generateAnnouncement(_pubKey, _privKey,
                MESSAGE, _seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _request1 = ContractGenerator.generateAnnouncement(_serverPubKey[0], _privKey,
                MESSAGE1, _seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _request2 = ContractGenerator.generateAnnouncement(_serverPubKey[1], _pubKey, _privKey,
                MESSAGE2, _seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _request3 = ContractGenerator.generateAnnouncement(_serverPubKey[2], _pubKey, _privKey,
                MESSAGE3, _seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);

        _request4 = ContractGenerator.generateAnnouncement(_serverPubKey[3], _pubKey, _privKey,
                MESSAGE4, _seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);
        _requests = new Contract.Announcement[4];
        _requests[0] = _request1;
        _requests[1] = _request2;
        _requests[2] = _request3;
        _requests[3] = _request4;

    }

    @Before
    public void setup() throws IOException, GeneralSecurityException, InterruptedException {

        _stubs = new PerfectStub[4];
        _impls = new ServiceDPASReliableImpl[4];
        _servers = new Server[4];
        _channels = new ManagedChannel[4];
        _executors = new ExecutorService[4];
        for (int i = 0; i < 4; i++) {
            var executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
            var eventGroup = new NioEventLoopGroup(1); //One thread for each channel
            executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
            _channels[i] = NettyChannelBuilder
                    .forAddress(host, port + i)
                    .executor(executor)
                    .channelType(NioSocketChannel.class)
                    .eventLoopGroup(eventGroup)
                    .usePlaintext()
                    .build();
            var stub = new PerfectStub(ServiceDPASGrpc.newStub(_channels[i]), _serverPubKey[i]);
            _stubs[i] = stub;
            _executors[i] = executor;
        }
        for (int i = 0; i < 4; i++) {
            var impl = new ServiceDPASReliableImpl(_serverPrivKey[i], Arrays.asList(_stubs),
                    Base64.getEncoder().encodeToString(_serverPubKey[i].getEncoded()), 1);
            _servers[i] = NettyServerBuilder.forPort(port + i).addService(impl).build();
            if (i != 3) {
                _servers[i].start();
            }
            _impls[i] = impl;
        }
        _stub = new QuorumStub(Arrays.asList(_stubs), 1);

        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));
    }

    @After
    public void teardown() {
        for (int i = 0; i < 4; i++) {
            _channels[i].shutdownNow();
            _executors[i].shutdownNow();
            if (i != 3)
                _servers[i].shutdownNow();

        }
    }

    @Test
    public void validPostGeneral() throws GeneralSecurityException, InterruptedException {
        _stub.postGeneral(_request);

        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        //Perform a read and wait for all servers to respond to garantee that all servers see the register
        CountDownLatch latch = new CountDownLatch(3);
        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(1, value.getAnnouncementsCount());
                    assertEquals(value.getAnnouncements(0).getMessage(), MESSAGE);
                    assertEquals(value.getAnnouncements(0).getSeq(), 0);
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    @Test
    public void validRepeatedPostGeneral() throws GeneralSecurityException, InterruptedException {
        _stub.postGeneral(_request);
        _stub.postGeneral(_request);
        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        //Perform a read and wait for all servers to respond to garantee that all servers see the register
        CountDownLatch latch = new CountDownLatch(3);
        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(1, value.getAnnouncementsCount());
                    assertEquals(value.getAnnouncements(0).getMessage(), MESSAGE);
                    assertEquals(value.getAnnouncements(0).getSeq(), 0);
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    @Test
    public void oneServerPostGeneral() throws InterruptedException, GeneralSecurityException {
        var req = _request.toBuilder().setMessage(CipherUtils.cipherAndEncode(MESSAGE.getBytes(), _stubs[1].getServerKey())).build();
        _stubs[1].postGeneral(req, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
            }

            @Override
            public void onError(Throwable t) {

            }

            @Override
            public void onCompleted() {

            }
        });

        Thread.sleep(2000);
        CountDownLatch latch = new CountDownLatch(3);

        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(0, value.getAnnouncementsCount());
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    @Test
    public void twoServerPostGeneral() throws InterruptedException, GeneralSecurityException {
        for (int i = 0; i < 2; i++) {
            var req = _request.toBuilder().setMessage(CipherUtils.cipherAndEncode(MESSAGE.getBytes(), _stubs[i].getServerKey())).build();
            _stubs[i].postGeneral(req, new StreamObserver<>() {
                @Override
                public void onNext(Contract.MacReply value) {
                }

                @Override
                public void onError(Throwable t) {

                }

                @Override
                public void onCompleted() {

                }
            });
        }

        Thread.sleep(2000);
        CountDownLatch latch = new CountDownLatch(3);

        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(0, value.getAnnouncementsCount());
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    @Test
    public void quorumServerPostGeneral() throws InterruptedException, GeneralSecurityException {
        final CountDownLatch latch = new CountDownLatch(3);
        for (int i = 0; i < 3; i++) {
            var req = _request.toBuilder().setMessage(CipherUtils.cipherAndEncode(MESSAGE.getBytes(), _stubs[i].getServerKey())).build();
            _stubs[i].postGeneral(req, new StreamObserver<>() {
                @Override
                public void onNext(Contract.MacReply value) {
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {

                }

                @Override
                public void onCompleted() {

                }
            });
        }
        latch.await();
        CountDownLatch latch2 = new CountDownLatch(3);


        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(1, value.getAnnouncementsCount());
                    assertEquals(value.getAnnouncements(0).getMessage(), MESSAGE);
                    assertEquals(value.getAnnouncements(0).getSeq(), 0);
                    latch2.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch2.await();
    }

    @Test
    public void allDiferentPosts() throws InterruptedException {
        for (int i = 0; i < 4; i++) {

            _stubs[i].postGeneral(_requests[i], new StreamObserver<>() {
                @Override
                public void onNext(Contract.MacReply value) {
                }

                @Override
                public void onError(Throwable t) {

                }

                @Override
                public void onCompleted() {

                }
            });
        }

        Thread.sleep(2000);

        CountDownLatch latch = new CountDownLatch(3);


        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(0, value.getAnnouncementsCount()); //Since client is bizantine, he tried to write diferent values in each server but could not
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    @Test
    public void weirdBizantineBehaviour() throws InterruptedException {
        for (int i = 0; i < 4; i++) {
            for (int j = i; j < 4; j++) {
                _stubs[i].postGeneral(_requests[j], new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.MacReply value) {
                    }

                    @Override
                    public void onError(Throwable t) {

                    }

                    @Override
                    public void onCompleted() {

                    }
                });
            }
        }

        Thread.sleep(2000);

        CountDownLatch latch = new CountDownLatch(3);


        var request = Contract.ReadRequest.newBuilder()
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        for (var stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(0, value.getAnnouncementsCount()); //Since client is bizantine, he tried to write diferent values in each server but could not
                    latch.countDown();
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }


}
