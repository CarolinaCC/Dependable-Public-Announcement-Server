package dpas.server.service;

import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.security.SecurityManager;
import dpas.utils.ContractGenerator;
import dpas.utils.link.PerfectStub;
import dpas.utils.link.QuorumStub;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
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
import java.util.concurrent.*;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class QuorumConcurrencyWithFaultTest {

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

    public QuorumConcurrencyWithFaultTest() {
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

        _users = new KeyPair[NUMBER_THREADS + 1];
        for (int i = 0; i < NUMBER_THREADS + 1; ++i) {
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
        for (int i = 0; i < 4; i++) {
            ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
            executor.setRejectedExecutionHandler(new ThreadPoolExecutor.DiscardPolicy());
            BindableService impl = new ServiceDPASSafeImpl(_serverPrivKey[i], manager);
            _servers[i] = NettyServerBuilder.forPort(port + i).addService(impl).build();
            _servers[i].start();
            _channels[i] = NettyChannelBuilder
                    .forAddress(host, port + i)
                    .executor(executor)
                    .usePlaintext()
                    .build();
            var stub = new PerfectStub(ServiceDPASGrpc.newStub(_channels[i]), _serverPubKey[i]);
            stubs[i] = stub;
            _executors[i] = executor;
        }
        _stub = new QuorumStub(Arrays.asList(stubs), 1);

        CountDownLatch latch = new CountDownLatch(NUMBER_THREADS * 4);
        for (var pstub : stubs) {
            //Register Users
            for (int i = 0; i < NUMBER_THREADS; i++) {
                pstub.register(ContractGenerator.generateRegisterRequest(_users[i].getPublic(), _users[i].getPrivate()), new StreamObserver<>() {
                    @Override
                    public void onNext(Contract.MacReply value) {

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
        }
        latch.await();
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
            var seq = _stub.getSeq(_stub.readGeneral(req).getAnnouncementsList());
            var request = ContractGenerator.generateAnnouncement(pub, priv,
                    MESSAGE, seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);
            try {
                _stub.postGeneral(request);
            } catch (RuntimeException e) {
                fail();
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
                    fail();
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        Thread.sleep(400);
        _servers[0].shutdownNow();
        for (Thread thread : threads) {
            thread.join();
        }

        Contract.ReadReply reply = _stub.readGeneral(
                Contract.ReadRequest.newBuilder()
                        .setNumber(0)
                        .build());
        //Check that each announcement was posted correctly
        assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS);

    }
}
