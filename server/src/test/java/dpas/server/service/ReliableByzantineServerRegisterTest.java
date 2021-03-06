package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.ErrorGenerator;
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

import static io.grpc.Status.CANCELLED;
import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class ReliableByzantineServerRegisterTest {
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

    private static final String host = "localhost";
    private static final int port = 9000;


    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[5][0];
    }

    public ReliableByzantineServerRegisterTest() {
    }

    @BeforeClass
    public static void oneTimeSetup() throws NoSuchAlgorithmException {
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
    }

    @Before
    public void setup() throws IOException {

        _stubs = new PerfectStub[4];
        _servers = new Server[4];
        _channels = new ManagedChannel[4];
        _executors = new ExecutorService[4];
        _impls = new ServiceDPASReliableImpl[3];

        var byzImpl = new ServiceDPASGrpc.ServiceDPASImplBase() {
            @Override
            public void postGeneral(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[0]));
            }

            @Override
            public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[0]));
            }

            @Override
            public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[0]));
            }

            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[0]));
            }

            @Override
            public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> responseObserver) {
                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[0]));
            }
        };
        _servers[0] = NettyServerBuilder.forPort(port).addService(byzImpl).build();
        _servers[0].start();
        var executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
        var eventGroup = new NioEventLoopGroup(1); //One thread for each channel
        executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
        _channels[0] = NettyChannelBuilder
                .forAddress(host, port)
                .executor(executor)
                .channelType(NioSocketChannel.class)
                .eventLoopGroup(eventGroup)
                .usePlaintext()
                .build();
        var stub = new PerfectStub(ServiceDPASGrpc.newStub(_channels[0]), _serverPubKey[0]);
        _stubs[0] = stub;
        _executors[0] = executor;
        for (int i = 1; i < 4; i++) {
            executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
            eventGroup = new NioEventLoopGroup(1); //One thread for each channel
            executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
            _channels[i] = NettyChannelBuilder
                    .forAddress(host, port + i)
                    .executor(executor)
                    .channelType(NioSocketChannel.class)
                    .eventLoopGroup(eventGroup)
                    .usePlaintext()
                    .build();
            var newStub = new PerfectStub(ServiceDPASGrpc.newStub(_channels[i]), _serverPubKey[i]);
            _stubs[i] = newStub;
            _executors[i] = executor;
        }

        for (int i = 1; i < 4; i++) {

            var impl = new ServiceDPASReliableImpl(_serverPrivKey[i], Arrays.asList(_stubs),
                    Base64.getEncoder().encodeToString(_serverPubKey[i].getEncoded()), 1);

            _servers[i] = NettyServerBuilder.forPort(port + i).addService(impl).build();
            _servers[i].start();
            _impls[i - 1] = impl;
        }

        _stub = new QuorumStub(Arrays.asList(_stubs), 1);

    }

    @After
    public void teardown() {
        for (int i = 0; i < 4; i++) {
            _channels[i].shutdownNow();
            _executors[i].shutdownNow();
            _servers[i].shutdownNow();

        }
    }

    @Test
    public void validRegister() throws GeneralSecurityException, InterruptedException {
        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));

        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        //Perform a read and wait for all servers to respond to garantee that all servers see the register
        CountDownLatch latch = new CountDownLatch(3);
        for (var stub : _stubs) {
            stub.read(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
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

        for (int i = 0; i < 3; i++) {

            assertEquals(_impls[i].getUsers().size(), 1);

        }
    }

    @Test
    public void invalidMacRegister() throws InterruptedException {
        new Thread(() -> {
            try {
                var req = ContractGenerator.generateRegisterRequest(_pubKey, _privKey);
                req = req.toBuilder().setMac(ByteString.copyFrom(new byte[]{1, 2, 3})).build();
                _stub.register(req);
            } catch (InterruptedException | GeneralSecurityException e) {
                fail();
            }
        }).start();

        Thread.sleep(1000);

        for (int i = 0; i < 3; i++) {
            assertEquals(_impls[i].getUsers().size(), 0);

        }
    }


    @Test
    public void invalidKeyRegister() throws InterruptedException {
        new Thread(() -> {
            try {
                var req = ContractGenerator.generateRegisterRequest(_pubKey, _privKey);
                req = req.toBuilder().setPublicKey(ByteString.copyFrom(new byte[]{1, 2, 3, 4})).build();
                _stub.register(req);
            } catch (InterruptedException | GeneralSecurityException e) {
                fail();
            }
        }).start();

        Thread.sleep(1000);
        for (var impl : _impls) {
            assertEquals(impl.getUsers().size(), 0);
        }
    }

    @Test
    public void validRepeatedRegister() throws GeneralSecurityException, InterruptedException {
        for (int i = 0; i < 5; i++) {
            _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));
        }

        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        //Perform a read and wait for all servers to respond to garantee that all servers see the register
        CountDownLatch latch = new CountDownLatch(3);
        for (var stub : _stubs) {
            stub.read(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
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

        for (int i = 0; i < 3; i++) {
            assertEquals(_impls[i].getUsers().size(), 1);
            assertNotNull(_impls[i].getUsers().get(_pubKey));

        }
    }

    @Test
    public void oneServerRegister() throws GeneralSecurityException, InterruptedException {
        _stubs[1].register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey), new StreamObserver<>() {
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

        for (int i = 0; i < 3; i++) {
            assertEquals(_impls[i].getUsers().size(), 0);
            assertNull(_impls[i].getUsers().get(_pubKey));
        }
    }

    @Test
    public void twoServerRegister() throws GeneralSecurityException, InterruptedException {
        _stubs[0].register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey), new StreamObserver<>() {
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
        _stubs[1].register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey), new StreamObserver<>() {
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
        for (int i = 0; i < 3; i++) {
            assertEquals(_impls[i].getUsers().size(), 0);
            assertNull(_impls[i].getUsers().get(_pubKey));

        }
    }

    @Test
    public void quorumWithByzServerRegister() throws GeneralSecurityException, InterruptedException {
        for (int i = 0; i < 3; i++) {
            _stubs[i].register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey), new StreamObserver<>() {
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
        for (int i = 0; i < 3; i++) {
            assertEquals(_impls[i].getUsers().size(), 0);
            assertNull(_impls[i].getUsers().get(_pubKey));

        }
    }
}
