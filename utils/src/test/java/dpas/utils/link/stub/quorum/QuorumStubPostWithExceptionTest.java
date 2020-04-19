package dpas.utils.link.stub.quorum;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.link.PerfectStub;
import dpas.utils.link.QuorumStub;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import io.grpc.util.MutableHandlerRegistry;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static io.grpc.Status.CANCELLED;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class QuorumStubPostWithExceptionTest {
    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry[] serviceRegistry = new MutableHandlerRegistry[4];

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PrivateKey _serverPrivKey[];
    private static PublicKey _serverPKey[];
    private static Contract.Announcement _request;
    private static List<Integer> _assertions = new ArrayList<>();

    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, CommonDomainException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        _serverPKey = new PublicKey[4];
        _serverPrivKey = new PrivateKey[4];

        for (int i = 0; i < 4; ++i) {
            KeyPair serverPair = keygen.generateKeyPair();
            _serverPKey[i] = serverPair.getPublic();
            _serverPrivKey[i] = serverPair.getPrivate();
        }

        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();

        _request = ContractGenerator.generateAnnouncement(_pubKey, _privKey,
                "m", 0, CipherUtils.keyToString(_pubKey), null);

    }

    @Before
    public void setup() {
        _assertions = new ArrayList<>();
    }

    @Test
    public void postNoExceptionsImmediateReply() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = allEmpyServers();
        var stubs = new ArrayList<PerfectStub>();
        int i = 0;
        for (var server : servers) {
            serviceRegistry[i] = new MutableHandlerRegistry();
            var registry = serviceRegistry[i];
            String serverName = InProcessServerBuilder.generateName();
            grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                    .fallbackHandlerRegistry(registry).directExecutor().build().start());
            registry.addService(server);
            ServiceDPASGrpc.ServiceDPASStub client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                    InProcessChannelBuilder.forName(serverName).directExecutor().build()));
            PerfectStub pstub = new PerfectStub(client, _serverPKey[i]);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        qstub.postWithException(_request);
        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 4);
    }

    @Test
    public void postOneExceptionImmediateReply() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = allEmpyServersOneException();
        var stubs = new ArrayList<PerfectStub>();
        int i = 0;
        for (var server : servers) {
            serviceRegistry[i] = new MutableHandlerRegistry();
            var registry = serviceRegistry[i];
            String serverName = InProcessServerBuilder.generateName();
            grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                    .fallbackHandlerRegistry(registry).directExecutor().build().start());
            registry.addService(server);
            ServiceDPASGrpc.ServiceDPASStub client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                    InProcessChannelBuilder.forName(serverName).directExecutor().build()));
            PerfectStub pstub = new PerfectStub(client, _serverPKey[i]);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        qstub.postWithException(_request);
        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 4);
    }

    @Test
    public void noConsensusThenConsensus() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = allEmpyServersTwoExceptionsThenSuccess();
        var stubs = new ArrayList<PerfectStub>();
        int i = 0;
        for (var server : servers) {
            serviceRegistry[i] = new MutableHandlerRegistry();
            var registry = serviceRegistry[i];
            String serverName = InProcessServerBuilder.generateName();
            grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                    .fallbackHandlerRegistry(registry).directExecutor().build().start());
            registry.addService(server);
            ServiceDPASGrpc.ServiceDPASStub client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                    InProcessChannelBuilder.forName(serverName).directExecutor().build()));
            PerfectStub pstub = new PerfectStub(client, _serverPKey[i]);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        qstub.postWithException(_request);
        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 12);
    }

    @Test(expected = RuntimeException.class)
    public void majorityException() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = allExceptionOneOk();
        var stubs = new ArrayList<PerfectStub>();
        int i = 0;
        for (var server : servers) {
            serviceRegistry[i] = new MutableHandlerRegistry();
            var registry = serviceRegistry[i];
            String serverName = InProcessServerBuilder.generateName();
            grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                    .fallbackHandlerRegistry(registry).directExecutor().build().start());
            registry.addService(server);
            ServiceDPASGrpc.ServiceDPASStub client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                    InProcessChannelBuilder.forName(serverName).directExecutor().build()));
            PerfectStub pstub = new PerfectStub(client, _serverPKey[i]);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        try {
            qstub.postWithException(_request);
        } catch (RuntimeException e) {
            for (int number : _assertions) {
                assertEquals(number, 1);
            }
            assertEquals(_assertions.size(), 4);
            assertEquals(e.getMessage(), "CANCELLED: Invalid security values provided");
            throw e;
        }
    }

    @Test(expected = RuntimeException.class)
    public void eventualExceptionConsensus() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = allExceptionsDifferentThenEqual();
        var stubs = new ArrayList<PerfectStub>();
        int i = 0;
        for (var server : servers) {
            serviceRegistry[i] = new MutableHandlerRegistry();
            var registry = serviceRegistry[i];
            String serverName = InProcessServerBuilder.generateName();
            grpcCleanup.register(InProcessServerBuilder.forName(serverName)
                    .fallbackHandlerRegistry(registry).directExecutor().build().start());
            registry.addService(server);
            ServiceDPASGrpc.ServiceDPASStub client = ServiceDPASGrpc.newStub(grpcCleanup.register(
                    InProcessChannelBuilder.forName(serverName).directExecutor().build()));
            PerfectStub pstub = new PerfectStub(client, _serverPKey[i]);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        try {
            qstub.postWithException(_request);
        } catch (RuntimeException e) {
            for (int number : _assertions) {
                assertEquals(number, 1);
            }
            assertEquals(_assertions.size(), 12);
            assertEquals(e.getMessage(), "CANCELLED: Invalid security values provided");
            throw e;
        }
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServers() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey[j]));
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException e) {
                                fail();
                            }
                        }
                    });
        }
        return servers;
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServersOneException() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey[j]));
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException e) {
                                fail();
                            }
                        }
                    });
        }
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                        _assertions.add(1);
                        responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[3]));

                    }
                });
        return servers;
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allExceptionOneOk() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            _assertions.add(1);
                            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[j]));
                        }
                    });
        }
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                        _assertions.add(1);
                        try {
                            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey[3]));
                        } catch (GeneralSecurityException e) {
                            fail();
                        }
                        responseObserver.onCompleted();
                    }
                });
        return servers;
    }



    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allExceptionsDifferentThenEqual() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final int j = i;
            AtomicInteger t = new AtomicInteger(j);
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            _assertions.add(1);

                            int k = t.getAndDecrement();
                            if (k <= 0) {
                                responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[j]));
                            } else {
                                responseObserver.onError(ErrorGenerator.generate(CANCELLED, UUID.randomUUID().toString(), request, _serverPrivKey[j]));
                            }
                        }
                    });
        }
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                        try {
                            _assertions.add(1);
                            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey[3]));
                            responseObserver.onCompleted();
                        } catch (GeneralSecurityException e) {
                            fail();
                        }
                    }
                });
        return servers;
    }


    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServersTwoExceptionsThenSuccess() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey[j]));
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException e) {
                                fail();
                            }
                        }
                    });
        }
        for (int i = 2; i < 4; i++) {
            final int j = i;

            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        AtomicInteger t = new AtomicInteger(2);

                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            if (j == 3) {
                                var curr = t.getAndDecrement();
                                if (curr == 0) {
                                    _assertions.add(1);
                                    try {
                                        responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey[j]));
                                    } catch (GeneralSecurityException e) {
                                        fail();
                                    }
                                    responseObserver.onCompleted();
                                    return;
                                }
                            }
                            _assertions.add(1);
                            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[j]));


                        }
                    });
        }
        return servers;
    }

}

