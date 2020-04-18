package dpas.utils.link.stub.quorum;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.MacGenerator;
import dpas.utils.link.PerfectStub;
import dpas.utils.link.QuorumStub;
import io.grpc.inprocess.InProcessChannelBuilder;
import io.grpc.inprocess.InProcessServerBuilder;
import io.grpc.stub.StreamObserver;
import io.grpc.testing.GrpcCleanupRule;
import io.grpc.util.MutableHandlerRegistry;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class QuorumStubReadTest {
    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry[] serviceRegistry = new MutableHandlerRegistry[4];

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;

    private static Contract.Announcement _request;
    private static Contract.Announcement _request2;
    private static final String MESSAGE = "Message";


    @BeforeClass
    public static void oneTimeSetup() throws GeneralSecurityException, CommonDomainException {
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);

        KeyPair serverPair = keygen.generateKeyPair();
        _serverPKey = serverPair.getPublic();
        _serverPrivKey = serverPair.getPrivate();

        KeyPair keyPair = keygen.generateKeyPair();
        _pubKey = keyPair.getPublic();
        _privKey = keyPair.getPrivate();

        _request = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, 1, CipherUtils.keyToString(_pubKey), null);

        //Decipher message
        String message = new String(CipherUtils.decodeAndDecipher(_request.getMessage(), _serverPrivKey), StandardCharsets.UTF_8);

        _request = _request.toBuilder()
                .setMessage(message)
                .build();

        _request2 = ContractGenerator.generateAnnouncement(_serverPKey, _pubKey, _privKey,
                MESSAGE, 2, CipherUtils.keyToString(_pubKey), null);

        //Decipher message
        message = new String(CipherUtils.decodeAndDecipher(_request2.getMessage(), _serverPrivKey), StandardCharsets.UTF_8);

        _request2 = _request2.toBuilder()
                .setMessage(message)
                .build();


    }

    @Test
    public void readAllEmpty() throws IOException, InterruptedException {
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
            PerfectStub pstub = new PerfectStub(client, _serverPKey);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        var reply = qstub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build());
        assertEquals(reply.getAnnouncementsList().size(), 0);
    }

    @Test
    public void readOneAndTwo() throws IOException, InterruptedException {
        var servers = oneAndTwo();
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
            PerfectStub pstub = new PerfectStub(client, _serverPKey);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);

        var reply = qstub.read(Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(_pubKey.getEncoded()))
                .setNumber(2)
                .build());
        assertEquals(reply.getAnnouncementsList().size(), 2);
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServers() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {

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
                    });
        }
        return servers;
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> oneAndTwo() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {

                        @Override
                        public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
                            try {

                                List<Contract.Announcement> announcements = new ArrayList<>();
                                announcements.add(_request);
                                responseObserver.onNext(Contract.ReadReply.newBuilder()
                                        .addAllAnnouncements(announcements)
                                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey)))
                                        .build());
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException | IOException e) {
                                fail();
                            }
                        }
                    });
        }
        for (int i = 0; i < 2; i++) {
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
                                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcements.size(), _serverPrivKey)))
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

}
