package dpas.utils.link.stub.quorum;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.auth.MacGenerator;
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

public class QuorumStubReadWithExceptionTest {

    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry[] serviceRegistry = new MutableHandlerRegistry[4];

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PrivateKey _serverPrivKey[];
    private static PublicKey _serverPKey[];
    private static Contract.Announcement _request;
    private static Contract.Announcement _request2;
    private static Contract.Announcement _request3;
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
                "MESSAGE", 1, CipherUtils.keyToString(_pubKey), null);

        _request2 = ContractGenerator.generateAnnouncement(_pubKey, _privKey,
                "MESSAGE", 2, CipherUtils.keyToString(_pubKey), null);

        _request3 = ContractGenerator.generateAnnouncement(_pubKey, _privKey,
                "MESSAGE", 3, CipherUtils.keyToString(_pubKey), null);

    }

    @Before
    public void setup() {
        _assertions = new ArrayList<>();
    }

    @Test
    public void readNoExceptionsImmediateReply() throws IOException, InterruptedException, GeneralSecurityException {
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

        var reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(3)
                .build());
        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 4);
        assertEquals(reply.getAnnouncementsList().size(), 0);
    }

    @Test
    public void readOneExceptionImmediateReply() throws IOException, InterruptedException, GeneralSecurityException {
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

        var reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(3)
                .build());
        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 4);
        assertEquals(0, reply.getAnnouncementsList().size());
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
        var reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(3)
                .build());
        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 12);
        assertEquals(0, reply.getAnnouncementsList().size());

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
        Contract.ReadReply reply = null;
        try {
            reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                    .setNumber(3)
                    .build());
        } catch (RuntimeException e) {
            for (int number : _assertions) {
                assertEquals(number, 1);
            }
            assertEquals(_assertions.size(), 4);
            assertEquals(e.getMessage(), "CANCELLED: Invalid security values provided");
            throw e;
        }
    }

    @Test
    public void eventualOkConsensusAfterException() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = allExceptionsDifferentThenEventualOKS();
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

        var reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(3)
                .build());

        for (int number : _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 12);
        assertEquals(0, reply.getAnnouncementsList().size());
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
        Contract.ReadReply reply = null;
        try {
            reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                    .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                    .setNumber(3)
                    .build());
        } catch (RuntimeException e) {
            for (int number : _assertions) {
                assertEquals(number, 1);
            }
            assertEquals(_assertions.size(), 12);
            assertEquals(e.getMessage(), "CANCELLED: Invalid security values provided");
            throw e;
        }
    }

    @Test
    public void readOneTwoAndThree() throws IOException, InterruptedException, GeneralSecurityException {
        var servers = oneAndTwoAndThree();
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

        var reply = qstub.readWithException(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(3)
                .build());
        assertEquals(reply.getAnnouncementsList().size(), 3);
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServersOneException() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                List<Contract.Announcement> announcements = new ArrayList<>();
                                responseObserver.onNext(Contract.ReadReply.newBuilder()
                                        .addAllAnnouncements(announcements)
                                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[j])))
                                        .build());
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException | IOException e) {
                                fail();
                            }
                        }
                    });
        }
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                        _assertions.add(1);
                        responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[3]));

                    }
                });
        return servers;
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> oneAndTwoAndThree() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();

        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                        try {
                            List<Contract.Announcement> announcements = new ArrayList<>();
                            announcements.add(_request);
                            responseObserver.onNext(Contract.ReadReply.newBuilder()
                                    .addAllAnnouncements(announcements)
                                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[0])))
                                    .build());
                            responseObserver.onCompleted();
                        } catch (GeneralSecurityException | IOException e) {
                            fail();
                        }
                    }
                });
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                        try {
                            List<Contract.Announcement> announcements = new ArrayList<>();
                            announcements.add(_request);
                            announcements.add(_request2);
                            responseObserver.onNext(Contract.ReadReply.newBuilder()
                                    .addAllAnnouncements(announcements)
                                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[1])))
                                    .build());
                            responseObserver.onCompleted();
                        } catch (GeneralSecurityException | IOException e) {
                            fail();
                        }
                    }
                });

        for (int i = 2; i < 4; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            try {
                                List<Contract.Announcement> announcements = new ArrayList<>();
                                announcements.add(_request);
                                announcements.add(_request2);
                                announcements.add(_request3);
                                responseObserver.onNext(Contract.ReadReply.newBuilder()
                                        .addAllAnnouncements(announcements)
                                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[j])))
                                        .build());
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException | IOException e) {
                                fail();
                            }
                        }
                    });
        }

        return servers;

    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServers() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                List<Contract.Announcement> announcements = new ArrayList<>();
                                responseObserver.onNext(Contract.ReadReply.newBuilder()
                                        .addAllAnnouncements(announcements)
                                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[j])))
                                        .build());
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException | IOException e) {
                                fail();
                            }
                        }
                    });
        }
        return servers;
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServersTwoExceptionsThenSuccess() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            final int j = i;
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                List<Contract.Announcement> announcements = new ArrayList<>();
                                responseObserver.onNext(Contract.ReadReply.newBuilder()
                                        .addAllAnnouncements(announcements)
                                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[j])))
                                        .build());
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException | IOException e) {
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
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            if (j == 3) {
                                var curr = t.getAndDecrement();
                                if (curr == 0) {
                                    _assertions.add(1);
                                    try {
                                        List<Contract.Announcement> announcements = new ArrayList<>();
                                        responseObserver.onNext(Contract.ReadReply.newBuilder()
                                                .addAllAnnouncements(announcements)
                                                .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[j])))
                                                .build());
                                    } catch (GeneralSecurityException | IOException e) {
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

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allExceptionsDifferentThenEventualOKS() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            final int j = i;
            AtomicInteger t = new AtomicInteger(j);
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            _assertions.add(1);
                            int k = t.getAndDecrement();
                            if (k <= 0) {
                                try {
                                    List<Contract.Announcement> announcements = new ArrayList<>();
                                    responseObserver.onNext(Contract.ReadReply.newBuilder()
                                            .addAllAnnouncements(announcements)
                                            .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[j])))
                                            .build());
                                } catch (GeneralSecurityException | IOException e) {
                                    fail();
                                }
                                responseObserver.onCompleted();
                            } else {
                                responseObserver.onError(ErrorGenerator.generate(CANCELLED, UUID.randomUUID().toString(), request, _serverPrivKey[j]));
                            }
                        }
                    });
        }
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                        _assertions.add(1);
                        responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[3]));
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
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
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
                    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                        try {
                            _assertions.add(1);
                            List<Contract.Announcement> announcements = new ArrayList<>();
                            responseObserver.onNext(Contract.ReadReply.newBuilder()
                                    .addAllAnnouncements(announcements)
                                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[3])))
                                    .build());
                            responseObserver.onCompleted();
                        } catch (GeneralSecurityException | IOException e) {
                            fail();
                        }
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
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            _assertions.add(1);
                            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _serverPrivKey[j]));
                        }
                    });
        }
        servers.add(
                new ServiceDPASGrpc.ServiceDPASImplBase() {
                    @Override
                    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                        _assertions.add(1);
                        try {
                            List<Contract.Announcement> announcements = new ArrayList<>();
                            responseObserver.onNext(Contract.ReadReply.newBuilder()
                                    .addAllAnnouncements(announcements)
                                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey[3])))
                                    .build());
                        } catch (GeneralSecurityException | IOException e) {
                            fail();
                        }
                        responseObserver.onCompleted();
                    }
                });
        return servers;
    }


}
