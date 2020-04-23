package dpas.utils.link.stub.perfect;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.auth.MacGenerator;
import dpas.utils.link.PerfectStub;
import io.grpc.Status;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import io.grpc.util.MutableHandlerRegistry;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static io.grpc.Status.CANCELLED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class PerfectStubReadWithExceptionTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry serviceRegistry = new MutableHandlerRegistry();

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;
    private static PublicKey _pubKey;

    private static final String MESSAGE = "Message";

    private static Contract.Announcement _request;
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


    }

    @Test
    public void readInvalidExceptionThenValidReply() throws IOException {
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
            public void read(Contract.ReadRequest readRequest, StreamObserver<Contract.ReadReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        List<Contract.Announcement> announcements = new ArrayList<>();
                        responseObserver.onNext(Contract.ReadReply.newBuilder()
                                .addAllAnnouncements(announcements)
                                .setMac(ByteString.copyFrom(MacGenerator.generateMac(readRequest, announcements.size(), _serverPrivKey)))
                                .build());
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(Status.UNKNOWN.asRuntimeException());

                } catch (GeneralSecurityException | IOException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.getAndIncrement();
            }

            @Override
            public void onError(Throwable t) {
                fail();
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
            assertEquals(countSuccess.get(), 1);
            assertEquals(countCompleted.get(), 1);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    public void readInvalidExceptionThenValidException() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countError = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new ServiceDPASGrpc.ServiceDPASImplBase() {
            final AtomicInteger i = new AtomicInteger(3);

            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

                int j = i.getAndDecrement();
                if (j == 0) {
                    responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey));
                    return;
                }
                responseObserver.onError(Status.UNKNOWN.asRuntimeException());
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                fail();
            }

            @Override
            public void onError(Throwable t) {
                countError.getAndIncrement();
                latch.countDown();

            }

            @Override
            public void onCompleted() {
                fail();
            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
            assertEquals(countError.get(), 1);
        } catch (InterruptedException e) {
            fail();
        }
    }


    @Test
    public void readImediateValidExceptionTest() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countError = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new ServiceDPASGrpc.ServiceDPASImplBase() {
            @Override
            public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey));
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                fail();
            }

            @Override
            public void onError(Throwable t) {
                countError.getAndIncrement();
                latch.countDown();
            }

            @Override
            public void onCompleted() {
                fail();
            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
            assertEquals(countError.get(), 1);
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    public void readValidImediateReply() throws IOException {

        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);
        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new ServiceDPASGrpc.ServiceDPASImplBase() {
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
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.incrementAndGet();
            }

            @Override
            public void onError(Throwable t) {
                fail();
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
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build(), new StreamObserver<>() {
            @Override
            public void onNext(Contract.ReadReply value) {
                countSuccess.incrementAndGet();
            }

            @Override
            public void onError(Throwable t) {
                fail();
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
            assertEquals(countSuccess.get(), 1);
            assertEquals(countCompleted.get(), 4);
        } catch (InterruptedException e) {
            fail();
        }
    }


}

