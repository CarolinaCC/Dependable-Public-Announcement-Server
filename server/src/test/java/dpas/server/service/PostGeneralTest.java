package dpas.server.service;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.ManagedChannel;
import io.grpc.Server;

import java.security.PublicKey;

import static org.junit.Assert.assertEquals;


public class PostGeneralTest {

    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    private Server _server;
    private PublicKey _firstPublicKey;
    private PublicKey _secondPublicKey;
    private byte[] _firstSignature;
    private byte[] _secondSignature;
    private byte[] _bigMessageSignature;

    private ManagedChannel _channel;

    private final static String FIRST_USER_NAME = "USER";
    private final static String SECOND_USER_NAME = "USER2";

    private static final String MESSAGE = "Message";
    private static final String SECOND_MESSAGE = "Second Message";
    private static final String INVALID_MESSAGE = "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid" +
            "ThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalidThisMessageIsInvalid";


}
