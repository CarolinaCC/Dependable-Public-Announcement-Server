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
import java.lang.reflect.Array;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.List;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class QuorumStubPostTest {
    @Rule
    public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

    private final MutableHandlerRegistry[] serviceRegistry = new MutableHandlerRegistry[4];

    private static PublicKey _pubKey;
    private static PrivateKey _privKey;
    private static PrivateKey _serverPrivKey;
    private static PublicKey _serverPKey;
    private static Contract.Announcement _request;
    private static List<Integer> _assertions = new ArrayList<>();

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
                "m", 0, CipherUtils.keyToString(_pubKey), null);

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
            PerfectStub pstub = new PerfectStub(client, _serverPKey);
            stubs.add(pstub);
            i++;
        }

        var qstub = new QuorumStub(stubs, 1);


        //Decipher message
        String message = new String(CipherUtils.decodeAndDecipher(_request.getMessage(), _serverPrivKey), StandardCharsets.UTF_8);

        _request = _request.toBuilder()
                .setMessage(message)
                .build();

        qstub.post(_request);
        for(int number: _assertions) {
            assertEquals(number, 1);
        }
        assertEquals(_assertions.size(), 4);
    }

    public static List<ServiceDPASGrpc.ServiceDPASImplBase> allEmpyServers() {
        List<ServiceDPASGrpc.ServiceDPASImplBase> servers = new ArrayList<>();
        for (int i = 0; i < 4; i++) {
            servers.add(
                    new ServiceDPASGrpc.ServiceDPASImplBase() {
                        @Override
                        public void post(Contract.Announcement request, StreamObserver<Contract.MacReply> responseObserver) {
                            try {
                                _assertions.add(1);
                                responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _serverPrivKey));
                                responseObserver.onCompleted();
                            } catch (GeneralSecurityException e) {
                                fail();
                            }
                        }
                    });
        }
        return servers;
    }

}
