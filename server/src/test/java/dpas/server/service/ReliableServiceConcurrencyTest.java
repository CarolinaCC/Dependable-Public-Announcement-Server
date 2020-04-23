package dpas.server.service;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.security.SecurityManager;
import dpas.utils.link.PerfectStub;
import dpas.utils.link.QuorumStub;
import dpas.utils.link.RegisterStub;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.channel.nio.NioEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.socket.nio.NioSocketChannel;
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

@RunWith(Parameterized.class)
public class ReliableServiceConcurrencyTest {

    private PerfectStub[] _stubs;
    private ServiceDPASReliableImpl[] _impls;

    private Server[] _servers;
    private RegisterStub _stub;

    private static PublicKey[] _serverPubKey;
    private static PrivateKey[] _serverPrivKey;

    private static KeyPair[] _users;

    private ManagedChannel[] _channels;

    private ExecutorService[] _executors;

    private static final String MESSAGE = "Message";

    private static final String host = "localhost";
    private static final int port = 9000;

    private static final int NUMBER_THREADS = 4;
    private static final int NUMBER_POSTS = NUMBER_THREADS * 5;

    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[5][0];
    }

    public ReliableServiceConcurrencyTest() {
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
            var impl = new ServiceDPASReliableImpl(_serverPrivKey[i], manager, Arrays.asList(_stubs),
                    Base64.getEncoder().encodeToString(_serverPubKey[i].getEncoded()), 1);
            _servers[i] = NettyServerBuilder.forPort(port + i).addService(impl).build();
            _servers[i].start();
            _impls[i] = impl;

        }
        _stub = new RegisterStub(new QuorumStub(Arrays.asList(_stubs), 1));

        for (int i = 0; i < NUMBER_THREADS; i++) {
            _stub.register(_users[i].getPublic(), _users[i].getPrivate());
        }
    }

    @After
    public void teardown() {
        for (int i = 0; i < 4; i++) {
            _channels[i].shutdownNow();
            _executors[i].shutdownNow();
            _servers[i].shutdownNow();

        }
    }


    private void postGeneralRun(int id) throws GeneralSecurityException, CommonDomainException, InterruptedException {
        PublicKey pub = _users[id].getPublic();
        PrivateKey priv = _users[id].getPrivate();
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
            _stub.postGeneral(pub, priv, MESSAGE, null);
        }
    }

    @Test
    public void concurrencyPostGeneralTest() throws InterruptedException, GeneralSecurityException {
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

        for (Thread thread : threads) {
            thread.join();
        }

        var reply = _stub.readGeneral(0);
        //Check that each announcement was posted correctly
        assertEquals(reply.length, NUMBER_POSTS);

    }

    private void postRun(int id) throws GeneralSecurityException, CommonDomainException, InterruptedException {
        PublicKey pub = _users[id].getPublic();
        PrivateKey priv = _users[id].getPrivate();
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
            _stub.post(pub, priv, MESSAGE, null);
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
                    fail();
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }

        for (var pair : _users) {
            var reply = _stub.read(pair.getPublic(), 0);
            //Check that each announcement was posted correctly
            assertEquals(reply.length, NUMBER_POSTS / NUMBER_THREADS);
        }
    }
}
