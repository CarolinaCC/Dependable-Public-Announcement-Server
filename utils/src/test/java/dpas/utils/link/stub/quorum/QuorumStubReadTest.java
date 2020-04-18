package dpas.utils.link.stub.quorum;

import com.google.protobuf.ByteString;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
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
import java.security.*;
import java.util.ArrayList;
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

    @Test
    public void readNoExceptionsImmediateReply() throws IOException, InterruptedException {
        var servers = allCorrectRead();
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

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allCorrectRead() {
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

}
