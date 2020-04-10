package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.session.Session;
import dpas.server.session.SessionManager;
import dpas.utils.CipherUtils;
import dpas.utils.ContractGenerator;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.Assert.*;

@RunWith(Parameterized.class)
public class SafeServiceConcurrencyTest {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;

    private static PublicKey _serverPubKey;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _publicKey;
    private static PrivateKey _privateKey;

    private static Session[] _sessions;

    private ManagedChannel _channel;

    private static final String MESSAGE = "Message";

    private static final String host = "localhost";
    private static final int port = 9000;

    private static final int NUMBER_THREADS = 20;
    private static final int NUMBER_POSTS = NUMBER_THREADS * 10;

    @Parameterized.Parameters
    public static Object[][] data() {
        return new Object[10][0];
    }

    public SafeServiceConcurrencyTest() {
    }

    @BeforeClass
    public static void oneTimeSetup() throws NoSuchAlgorithmException {
        // Keys
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair keyPair = keygen.generateKeyPair();
        _serverPubKey = keyPair.getPublic();
        _serverPrivKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _publicKey = keyPair.getPublic();
        _privateKey = keyPair.getPrivate();

        _sessions = new Session[NUMBER_THREADS + 1];
        for (int i = 0; i < NUMBER_THREADS + 1; ++i) {
            Session session = new Session(new SecureRandom().nextLong(), _publicKey, UUID.randomUUID().toString(), LocalDateTime.now().plusHours(2));
            _sessions[i] = session;
        }
    }

    @Before
    public void setup() throws GeneralSecurityException, IOException {

        SessionManager manager = new SessionManager(50000000);
        for (int i = 0; i < NUMBER_THREADS + 1; ++i) {
            manager.getSessions().put(_sessions[i].getSessionNonce(), _sessions[i]);
        }

        final BindableService impl = new ServiceDPASSafeImpl(_serverPrivKey, manager);
        _server = NettyServerBuilder.forPort(port).addService(impl).build();
        _server.start();

        _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
        _stub = ServiceDPASGrpc.newBlockingStub(_channel);

        //Register Users
        _stub.safeRegister(ContractGenerator.generateRegisterRequest(_sessions[NUMBER_THREADS].getSessionNonce(),
                _sessions[NUMBER_THREADS].getSequenceNumber() + 1, _publicKey, _privateKey));
    }

    @After
    public void teardown() {
        _server.shutdown();
        _channel.shutdown();
    }


    private void postRun(int id) throws GeneralSecurityException, IOException, CommonDomainException {
        long seq = _sessions[id].getSequenceNumber() + 1;
        String nonce = _sessions[id].getSessionNonce();
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
            var request = ContractGenerator.generatePostRequest(_serverPubKey, _publicKey, _privateKey,
                    MESSAGE, nonce, seq, CipherUtils.keyToString(_publicKey), null);

            _stub.safePost(request);
            seq += 2;
        }
    }

    private void postGeneralRun(int id) throws GeneralSecurityException, IOException, CommonDomainException {
        long seq = _sessions[id].getSequenceNumber() + 1;
        String nonce = _sessions[id].getSessionNonce();
        for (int i = 0; i < NUMBER_POSTS / NUMBER_THREADS; i++) {
            var request = ContractGenerator.generatePostRequest(_serverPubKey, _publicKey, _privateKey,
                    MESSAGE, nonce, seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, null);
            _stub.safePostGeneral(request);
            seq += 2;
        }
    }

    @Test
    public void concurrencyPostTest() throws InterruptedException {
        Thread[] threads = new Thread[NUMBER_THREADS];
        HashSet<Integer> sequencers = new HashSet<>();
        for (int i = 0; i < NUMBER_THREADS; i++) {
            final int id = i;
            threads[id] = new Thread(() -> {
                try {
                    postRun(id);
                } catch (CommonDomainException | IOException | GeneralSecurityException e) {
                    fail();
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }

        Contract.ReadReply reply = _stub.read(
                Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
                        .setNumber(NUMBER_POSTS * 2)
                        .build());
        //Check that each announcement was posted correctly
        assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS);

        //Check that each announcement was posted correctly
        for (var announcement : reply.getAnnouncementsList()) {
            assertEquals(announcement.getMessage(), MESSAGE);
            assertArrayEquals(announcement.getPublicKey().toByteArray(), _publicKey.getEncoded());
            assertTrue(announcement.getSequencer() >= 0);
            assertTrue(announcement.getSequencer() < NUMBER_POSTS);
            assertFalse(sequencers.contains(announcement.getSequencer()));
            sequencers.add(announcement.getSequencer());
        }
    }


    @Test
    public void concurrencyPostGeneralTest() throws InterruptedException {
        Thread[] threads = new Thread[NUMBER_THREADS];
        HashSet<Integer> sequencers = new HashSet<>();
        for (int i = 0; i < NUMBER_THREADS; i++) {
            final int id = i;
            threads[i] = new Thread(() -> {
                try {
                    postGeneralRun(id);
                } catch (CommonDomainException | IOException | GeneralSecurityException e) {
                    fail();
                }
            });
        }

        Stream.of(threads).forEach(Thread::start);

        for (Thread thread : threads) {
            thread.join();
        }

        Contract.ReadReply reply = _stub.readGeneral(
                Contract.ReadRequest.newBuilder()
                        .setNumber(NUMBER_POSTS * 2)
                        .build());
        //Check that each announcement was posted correctly
        assertEquals(reply.getAnnouncementsCount(), NUMBER_POSTS);

        //Check that each announcement was posted correctly
        for (var announcement : reply.getAnnouncementsList()) {
            assertEquals(announcement.getMessage(), MESSAGE);
            assertArrayEquals(announcement.getPublicKey().toByteArray(), _publicKey.getEncoded());
            assertTrue(announcement.getSequencer() >= 0);
            assertTrue(announcement.getSequencer() < NUMBER_POSTS);
            assertFalse(sequencers.contains(announcement.getSequencer()));
            sequencers.add(announcement.getSequencer());
        }
    }
}
