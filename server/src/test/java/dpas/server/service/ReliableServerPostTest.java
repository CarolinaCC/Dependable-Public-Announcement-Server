package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.security.SecurityManager;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class ReliableServerPostTest {
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

    private static long _seq = 0;

    private static final String MESSAGE = "MESSAGE";

    private static final String host = "localhost";
    private static final int port = 9000;


    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[5][0];
    }

    public ReliableServerPostTest() {
    }

    @BeforeClass
    public static void oneTimeSetup() throws NoSuchAlgorithmException, CommonDomainException {
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
                MESSAGE, _seq, CipherUtils.keyToString(_pubKey), null);
    }

    @Before
    public void setup() throws IOException, GeneralSecurityException, InterruptedException {

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
        _stub = new QuorumStub(Arrays.asList(_stubs), 1);

        _stub.register(ContractGenerator.generateRegisterRequest(_pubKey, _privKey));
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
    public void validPost() throws GeneralSecurityException, InterruptedException {
        _stub.post(_request);

        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(0)
                .setNonce("Nonce1")
                .build();

        //Perform a read and wait for all servers to respond to garantee that all servers see the register

        Thread.sleep(2000);

        CountDownLatch latch = new CountDownLatch(4);
        for (var stub : _stubs) {
            stub.read(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    assertEquals(1, value.getAnnouncementsCount());
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
