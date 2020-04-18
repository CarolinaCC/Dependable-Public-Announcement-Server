package dpas.utils.link;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
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
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static io.grpc.Status.CANCELLED;
import static org.junit.Assert.*;


public class PerfectStubPostTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry serviceRegistry = new MutableHandlerRegistry();

    private static PrivateKey _invalidPrivKey;
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PublicKey _secondPubKey;
    private static PrivateKey _secondPrivKey;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;
    private static PublicKey _invalidPubKey;

    private static String _secondNonce;
    private static long _secondSeq;

    private static String _nonce;
    private static long _seq;
    private static String _invalidNonce;

    private static final String MESSAGE = "Message";
    private static final String LONGMESSAGE = "A".repeat(255);

    private static Contract.Announcement _nonUserequest;
    private static Contract.Announcement _request;
    private static Contract.Announcement _futureRequest;
    private static Contract.Announcement _longRequest;
    private static Contract.Announcement _invalidPubKeyRequest;

    private static final int port = 9001;
    private static final String host = "localhost";

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
    private Server _server;
    private ManagedChannel _channel;

    private ServiceDPASGrpc.ServiceDPASStub client;


    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, CommonDomainException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        _nonce = UUID.randomUUID().toString();
        _secondNonce = UUID.randomUUID().toString();
        _invalidNonce = UUID.randomUUID().toString();
        _seq = 1;
        _secondSeq = 1;

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();

        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _secondPubKey = keyPair.getPublic();
        _secondPrivKey = keyPair.getPrivate();

        keyPair = keygen.generateKeyPair();
        _invalidPubKey = keyPair.getPublic();
        _invalidPrivKey = keyPair.getPrivate();

        _request = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, _seq, CipherUtils.keyToString(_pubKey), null);

        _nonUserequest = ContractGenerator.generateAnnouncement(_serverPKey, _secondPubKey, _secondPrivKey,
                MESSAGE, _secondSeq, CipherUtils.keyToString(_secondPubKey), null);

        _longRequest = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                LONGMESSAGE, _seq, CipherUtils.keyToString(_pubKey), null);

        _invalidPubKeyRequest = ContractGenerator.generateAnnouncement(_serverPKey, _invalidPubKey, _invalidPrivKey,
                MESSAGE, _seq, CipherUtils.keyToString(_pubKey), null);

        _futureRequest = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, _seq + 2, CipherUtils.keyToString(_pubKey), null);

    }

    @Test
    public void postInvalidExceptionTest() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);
        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(Status.UNKNOWN.asRuntimeException());

                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.post(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
    public void postValidExceptionTest() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);
        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _secondPrivKey));

                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.post(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
    public void postValidImediateReply() throws IOException {

        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);
        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            @Override
            public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                    responseObserver.onCompleted();
                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.post(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
    public void postInvalidReply3TimesThenValid() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);

        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                    } else {
                        //Just send an invalid mac reply
                        responseObserver.onNext(Contract.MacReply.newBuilder().build());
                    }
                    responseObserver.onCompleted();
                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.post(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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

    @Test
    public void postGeneralTest() throws IOException {
        String serverName = InProcessServerBuilder.generateName();
        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());
        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));
        PerfectStub pstub = new PerfectStub(client, _serverPKey);
        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void postGeneral(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(Status.UNKNOWN.asRuntimeException());

                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.postGeneral(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                latch.countDown();
            }

            @Override
            public void onError(Throwable t) {
                fail();
            }

            @Override
            public void onCompleted() {

            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    public void postGeneralValidExceptionTest() throws IOException {
        String serverName = InProcessServerBuilder.generateName();
        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());
        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));
        PerfectStub pstub = new PerfectStub(client, _serverPKey);
        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void postGeneral(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                        responseObserver.onCompleted();
                        return;
                    }
                    responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _secondPrivKey));

                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.postGeneral(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
                latch.countDown();
            }

            @Override
            public void onError(Throwable t) {
                fail();
            }

            @Override
            public void onCompleted() {

            }
        });

        try {
            if (!latch.await(4000, TimeUnit.SECONDS)) {
                fail();
            }
        } catch (InterruptedException e) {
            fail();
        }
    }

    @Test
    public void postGeneralValidImediateReply() throws IOException {

        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);
        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            @Override
            public void postGeneral(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                    responseObserver.onCompleted();
                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.postGeneral(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
    public void postGeneralInvalidReply3TimesThenValid() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countSuccess = new AtomicInteger(0);

        final AtomicInteger countCompleted = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new  ServiceDPASGrpc.ServiceDPASImplBase() {
            AtomicInteger i = new AtomicInteger(3);
            @Override
            public void postGeneral(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                    } else {
                        //Just send an invalid mac reply
                        responseObserver.onNext(Contract.MacReply.newBuilder().build());
                    }
                    responseObserver.onCompleted();
                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.postGeneral(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
