package dpas.utils.link.stub.perfect;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.auth.MacGenerator;
import dpas.utils.link.PerfectStub;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import io.grpc.util.MutableHandlerRegistry;
import org.junit.*;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import static io.grpc.Status.CANCELLED;
import static io.grpc.Status.INVALID_ARGUMENT;
import static org.junit.Assert.*;

public class PerfectStubReadTest {
    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry serviceRegistry = new MutableHandlerRegistry();

    private static Throwable assertThrowable = null;

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;


    private ServiceDPASGrpc.ServiceDPASStub client;


    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();

        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();

    }

    @AfterClass
    public static void oneTimeTeardown() {

    }

    @Before
    public void setup() throws IOException {
    }

    @Test
    public void readInvalidExceptionThenValidReply() throws IOException {
        String serverName = InProcessServerBuilder.generateName();
        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());
        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));
        PerfectStub pstub = new PerfectStub(client, _serverPKey);
        final AtomicInteger countCompleted = new AtomicInteger(0);
        final AtomicInteger countSuccess = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);

            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        List<Contract.Announcement> announcements = new ArrayList<>();
                        responseObserver.onNext(Contract.ReadReply.newBuilder()
                                .addAllAnnouncements(announcements)
                                .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey)))
                                .build());
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(Status.UNKNOWN.asRuntimeException());

                } catch (GeneralSecurityException | IOException e) {
                    assertThrowable = e;
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.getAndIncrement();
            }

            @Override
            public void onError(Throwable t) {
                assertThrowable = t;
            }

            @Override
            public void onCompleted() {
                countCompleted.getAndIncrement();
                latch.countDown();
            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
            assertNull(assertThrowable);
            assertEquals(countSuccess.get(), 1);
            assertEquals(countCompleted.get(), 1);
        } catch (InterruptedException e) {
            fail();
        }
    }


    @Test
    public void readValidExceptionsThenReply() throws IOException {
        String serverName = InProcessServerBuilder.generateName();
        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());
        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));
        PerfectStub pstub = new PerfectStub(client, _serverPKey);
        final AtomicInteger countCompleted = new AtomicInteger(0);
        final AtomicInteger countSuccess = new AtomicInteger(0);
        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        List<Contract.Announcement> announcements = new ArrayList<Contract.Announcement>();
                        responseObserver.onNext(Contract.ReadReply.newBuilder()
                                .addAllAnnouncements(announcements)
                                .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey)))
                                .build());
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey));

                } catch (GeneralSecurityException | IOException e) {
                    assertThrowable = e;
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.getAndIncrement();
            }

            @Override
            public void onError(Throwable t) {
                assertThrowable = t;
            }

            @Override
            public void onCompleted() {
                countCompleted.getAndIncrement();
                latch.countDown();
            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
            assertNull(assertThrowable);
            assertEquals(countSuccess.get(), 1);
            assertEquals(countCompleted.get(), 1);
        } catch (InterruptedException e) {
            fail();
        }
    }


    @Test
    public void readNoExceptionsImmediateReply() throws IOException {
        String serverName = InProcessServerBuilder.generateName();
        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());
        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));
        PerfectStub pstub = new PerfectStub(client, _serverPKey);
        final AtomicInteger countCompleted = new AtomicInteger(0);
        final AtomicInteger countSuccess = new AtomicInteger(0);
        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                try {
                    List<Contract.Announcement> announcements = new ArrayList<>();
                    responseObserver.onNext(Contract.ReadReply.newBuilder()
                            .addAllAnnouncements(announcements)
                            .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey)))
                            .build());
                    responseObserver.onCompleted();

                } catch (GeneralSecurityException | IOException e) {
                    assertThrowable = e;
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.read(Contract.ReadRequest.newBuilder()
                        .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                        .setNumber(2)
                        .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.getAndIncrement();
            }

            @Override
            public void onError(Throwable t) {
                assertThrowable = t;
            }

            @Override
            public void onCompleted() {
                countCompleted.getAndIncrement();
                latch.countDown();
            }
        });


        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
            assertNull(assertThrowable);
            assertEquals(countSuccess.get(), 1);
            assertEquals(countCompleted.get(), 1);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    public void readInvalidReply3TimesThenValid() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);

        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new ServiceDPASGrpc.ServiceDPASImplBase() {
            final AtomicInteger i = new AtomicInteger(3);

            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        List<Contract.Announcement> announcements = new ArrayList<>();
                        responseObserver.onNext(Contract.ReadReply.newBuilder()
                                .addAllAnnouncements(announcements)
                                .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey)))
                                .build());
                    } else {
                        responseObserver.onNext(Contract.ReadReply.newBuilder().build());
                    }
                    responseObserver.onCompleted();
                } catch (GeneralSecurityException | IOException e) {
                    assertThrowable = e;
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.incrementAndGet();
            }

            @Override
            public void onError(Throwable t) {
                assertThrowable = t;
            }

            @Override
            public void onCompleted() {
                countCompleted.getAndIncrement();
                latch.countDown();
            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
            assertNull(assertThrowable);
            assertEquals(countSuccess.get(), 1);
            assertEquals(countCompleted.get(), 4);
        } catch (InterruptedException e) {
            fail();
        }
    }


}
