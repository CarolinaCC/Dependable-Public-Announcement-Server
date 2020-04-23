package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.security.SecurityManager;
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
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.stream.Stream;

import static io.grpc.Status.CANCELLED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

@RunWith(Parameterized.class)
public class QuorumConcurrencyWithByzantineFailTest {

    private Throwable assertThrowable = null;

    private Server[] _servers;
    private QuorumStub _stub;

    private static PublicKey[] _serverPubKey;
    private static PrivateKey[] _serverPrivKey;

    private static KeyPair[] _users;

    private ManagedChannel[] _channels;

    private ExecutorService[] _executors;

    private static final String MESSAGE = "Message";

    private static final String host = "localhost";
    private static final int port = 9000;

    private static final int NUMBER_THREADS = 4;
    private static final int NUMBER_POSTS = NUMBER_THREADS * 10;

    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[5][0];
    }

    public QuorumConcurrencyWithByzantineFailTest() {
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

        _users = new KeyPair[NUMBER_THREADS];
        for (int i = 0; i < NUMBER_THREADS; ++i) {
            _users[i] = keygen.generateKeyPair();
        }
    }

    @Before
    public void setup() throws GeneralSecurityException, IOException, InterruptedException {

        SecurityManager manager = new SecurityManager();

        PerfectStub[] stubs = new PerfectStub[4];
        _servers = new Server[4];
        _channels = new ManagedChannel[4];
        _executors = new ExecutorService[4];

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
        stubs[0] = stub;
        _executors[0] = executor;

        for (int i = 1; i < 4; i++) {
            executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
            executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
            eventGroup = new NioEventLoopGroup(1); //One thread for each channel
            var impl = new ServiceDPASSafeImpl(_serverPrivKey[i], manager);
            _servers[i] = NettyServerBuilder.forPort(port + i).addService(impl).build();
            _servers[i].start();
            _channels[i] = NettyChannelBuilder
                    .forAddress(host, port + i)
                    .executor(executor)
                    .channelType(NioSocketChannel.class)
                    .eventLoopGroup(eventGroup)
                    .usePlaintext()
                    .build();
            stub = new PerfectStub(ServiceDPASGrpc.newStub(_channels[i]), _serverPubKey[i]);
            stubs[i] = stub;
            _executors[i] = executor;
        }
        _stub = new QuorumStub(Arrays.asList(stubs), 1);

        for (int i = 0; i < NUMBER_THREADS; i++) {
            _stub.register(ContractGenerator.generateRegisterRequest(_users[i].getPublic(), _users[i].getPrivate()));
        }
    }

    @After
    public void teardown() {
        for (int i = 0; i < 4; i++) {
            _executors[i].shutdownNow();
            _channels[i].shutdownNow();
            _servers[i].shutdownNow();

        }
    }


    private void postGeneralRun(int id) throws GeneralSecurityException, CommonDomainException, InterruptedException {
        PublicKey pub = _users[id].getPublic();
        PrivateKey priv = _users[id].getPrivate();
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
            var req = Contract.ReadRequest.newBuilder()
                    .setNumber(1)
                    .setNonce("Nonce")
                    .build();
            var reply = _stub.readGeneral(req);
            var seq = _stub.getSeq(reply.getAnnouncementsList());
            var a = reply.getAnnouncementsList().toArray(new Contract.Announcement[reply.getAnnouncementsCount()]);
            var request = ContractGenerator.generateAnnouncement(pub, priv, MESSAGE,
                    seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, a);
            try {
                _stub.postGeneral(request);
            } catch (RuntimeException e) {
                assertThrowable = e;
            }
        }
    }

    @Test
    public void concurrencyPostGeneralTest() throws InterruptedException {
        Thread[] threads = new Thread[NUMBER_THREADS];
        for (int i = 0; i < NUMBER_THREADS; i++) {
            final int id = i;
            threads[i] = new Thread(() -> {
                try {
                    postGeneralRun(id);
                } catch (CommonDomainException | GeneralSecurityException | InterruptedException e) {
                    assertThrowable = e;
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }

        Contract.ReadReply reply = _stub.readGeneral(
                Contract.ReadRequest.newBuilder()
                        .setNumber(0)
                        .build());
        //Check that each announcement was posted correctly
        assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS);
        assertNull(assertThrowable);
    }


    private void postRun(int id) throws GeneralSecurityException, CommonDomainException, InterruptedException {
        PublicKey pub = _users[id].getPublic();
        PrivateKey priv = _users[id].getPrivate();
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
            var req = Contract.ReadRequest.newBuilder()
                    .setNumber(1)
                    .setNonce("Nonce")
                    .setPublicKey(ByteString.copyFrom(pub.getEncoded()))
                    .build();
            var reply = _stub.read(req);
            var seq = _stub.getSeq(reply.getAnnouncementsList());
            var a = reply.getAnnouncementsList().toArray(new Contract.Announcement[reply.getAnnouncementsCount()]);
            var request = ContractGenerator.generateAnnouncement(pub, priv,
                    MESSAGE, seq, Base64.getEncoder().encodeToString(pub.getEncoded()), a);
            try {
                _stub.post(request);
            } catch (RuntimeException e) {
                assertThrowable = e;
            }
        }
    }

    @Test
    public void concurrencyPostTest() throws InterruptedException, GeneralSecurityException {
        Thread[] threads = new Thread[NUMBER_THREADS];
        for (int i = 0; i < NUMBER_THREADS; i++) {
            final int id = i;
            threads[i] = new Thread(() -> {
                try {
                    postRun(id);
                } catch (CommonDomainException | GeneralSecurityException | InterruptedException e) {
                    assertThrowable = e;
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }

        for (var pair : _users) {
            var reply = _stub.read(Contract.ReadRequest.newBuilder()
                    .setNumber(0)
                    .setPublicKey(ByteString.copyFrom(pair.getPublic().getEncoded()))
                    .build());
            //Check that each announcement was posted correctly
            assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS / NUMBER_THREADS);
            assertNull(assertThrowable);
            _stub.post(reply.getAnnouncements(reply.getAnnouncementsCount() - 1)); //Write Back like a atomic register
        }
    }
}
