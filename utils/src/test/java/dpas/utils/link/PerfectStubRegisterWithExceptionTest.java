package dpas.utils.link;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
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
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static io.grpc.Status.CANCELLED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class PerfectStubRegisterWithExceptionTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry serviceRegistry = new MutableHandlerRegistry();

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;


    private static Contract.RegisterRequest _request;

    private ServiceDPASGrpc.ServiceDPASStub client;


    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();

        KeyPair keyPair = keygen.generateKeyPair();
        PublicKey _pubKey = keyPair.getPublic();
        PrivateKey _privKey = keyPair.getPrivate();


        _request = ContractGenerator.generateRegisterRequest(_pubKey, _privKey);

    }

    @Test
    public void registerInvalidExceptionThenValidReply() throws IOException {
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
            public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _serverPrivKey));
                        responseObserver.onCompleted();
                    } else {
                        //Just send an invalid mac reply
                        responseObserver.onError(Status.UNKNOWN.asRuntimeException());
                    }
                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);
        pstub.registerWithException(_request, new StreamObserver<>() {
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
    public void registerInvalidExceptionThenValidExceptionTest() throws IOException {
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
            public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> responseObserver) {
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
        pstub.registerWithException(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
    public void registerValidExceptionTest() throws IOException {
        String serverName = InProcessServerBuilder.generateName();

        grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                .fallbackHandlerRegistry(serviceRegistry).directExecutor().build().start());

        client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                InProcessChannelBuilder.forName(serverName).directExecutor().build()));

        PerfectStub pstub = new PerfectStub(client, _serverPKey);

        final AtomicInteger countError = new AtomicInteger(0);

        ServiceDPASGrpc.ServiceDPASImplBase impl = new ServiceDPASGrpc.ServiceDPASImplBase() {

            @Override
            public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> responseObserver) {
                    responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey));
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.registerWithException(_request, new StreamObserver<>() {
            @Override
            public void onNext(Contract.MacReply value) {
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
    public void registerValidImediateReply() throws IOException {

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
            public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _serverPrivKey));
                    responseObserver.onCompleted();
                } catch (GeneralSecurityException e) {
                    fail();
                }
            }
        };
        serviceRegistry.addService(impl);
        CountDownLatch latch = new CountDownLatch(1);

        pstub.registerWithException(_request, new StreamObserver<>() {
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
    public void registerInvalidReply3TimesThenValid() throws IOException {
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
            public void register(Contract.RegisterRequest request, StreamObserver<Contract.MacReply> responseObserver) {
                try {
                    int j = i.getAndDecrement();
                    if (j == 0) {
                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _serverPrivKey));
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
        pstub.registerWithException(_request, new StreamObserver<>() {
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

