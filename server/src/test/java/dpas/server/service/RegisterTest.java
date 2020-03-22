package dpas.server.service;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class RegisterTest {

	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
	private Server _server;
	private PublicKey _firstPublicKey;
	private PublicKey _secondPublicKey;
	private PublicKey _publicDSAKey;
	private ManagedChannel _channel;


	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Before
	public void setup() throws IOException, NoSuchAlgorithmException {

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		_firstPublicKey = keyPair.getPublic();

		keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		keyPair = keygen.generateKeyPair();
		_secondPublicKey = keyPair.getPublic();

		final BindableService impl = new ServiceDPASImpl();

		// Start server
		_server = NettyServerBuilder.forPort(9000).addService(impl).build();
		_server.start();

		keygen = KeyPairGenerator.getInstance("DSA");
		keygen.initialize(1024);
		keyPair = keygen.generateKeyPair();
		_publicDSAKey = keyPair.getPublic();

		final String host = "localhost";
		final int port = 9000;
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

	}

	@After
	public void teardown() {
		_server.shutdown();
		_channel.shutdown();
	}

	@Test
	public void registerSuccess() {
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.build());
	}

	@Test
	public void registerTwoUsers() {
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.build());

		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.build());
	}

	@Test
	public void registerNullKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");
		_stub.register(Contract.RegisterRequest.newBuilder().build());
	}

	@Test
	public void registerEmptyKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(new byte[0]))
				.build());
	}

	@Test
	public void registerArbitraryKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: invalid key format");
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(new byte[] { 12, 2, 12, 5 }))
				.build());
	}

	@Test
	public void registerWrongAlgorithmKey() throws NoSuchAlgorithmException {

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Invalid RSA public key");

		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicDSAKey.getEncoded()))
				.build());
	}

	@Test
	public void registerRepeatedUser() {
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.build());
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: User Already Exists");

		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.build());
	}

}
