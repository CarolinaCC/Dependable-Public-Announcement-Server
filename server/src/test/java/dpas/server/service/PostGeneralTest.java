package dpas.server.service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
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

public class PostGeneralTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

	private Server _server;
	private PublicKey _firstPublicKey;
	private PublicKey _secondPublicKey;
	private byte[] _firstSignature;
	private byte[] _secondSignature;
	private byte[] _bigMessageSignature;

	private ManagedChannel _channel;

	private static final String MESSAGE = "Message";
	private static final String SECOND_MESSAGE = "Second Message";
	private static final String INVALID_MESSAGE = StringUtils.repeat("ThisMessageisInvalid", "", 15);
	
	@Before
	public void setup() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		_firstPublicKey = keyPair.getPublic();

		// generate first signature
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(keyPair.getPrivate());
		sign.update(MESSAGE.getBytes());
		_firstSignature = sign.sign();

		// second key pair
		keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		keyPair = keygen.generateKeyPair();
		_secondPublicKey = keyPair.getPublic();

		// Generate second signature
		sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(keyPair.getPrivate());
		sign.update(SECOND_MESSAGE.getBytes());
		_secondSignature = sign.sign();

		// Generate signature for too big message
		sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(keyPair.getPrivate());
		sign.update(INVALID_MESSAGE.getBytes());
		_bigMessageSignature = sign.sign();


		final BindableService impl = new ServiceDPASImpl();

		// Start server
		_server = NettyServerBuilder.forPort(9000).addService(impl).build();
		_server.start();

		final String host = "localhost";
		final int port = 9000;
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

		// create first user
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded())).build());

		// create second user
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.build());

	}

	@After
	public void teardown() {
		_server.shutdown();
		_channel.shutdown();
	}

	@Test
	public void postSuccess() {
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(UUID.randomUUID().toString())
				.build());
	}

	@Test
	public void twoPostsSuccess() {
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(UUID.randomUUID().toString())
				.build());

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setIdentifier(UUID.randomUUID().toString())
				.setMessage(SECOND_MESSAGE).setSignature(ByteString.copyFrom(_secondSignature))
				.build());
	}

	@Test
	public void twoPostsWithReference() {
		String firstIdentifier = UUID.randomUUID().toString();
		String secondIdentifier = UUID.randomUUID().toString();
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(firstIdentifier)
				.build());


		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.setIdentifier(secondIdentifier)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.build());
	}

	@Test
	public void twoPostsSameIdentifier() {
		String firstIdentifier = UUID.randomUUID().toString();
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(firstIdentifier)
				.build());

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Post Identifier Already Exists");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.setIdentifier(firstIdentifier)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.build());
	}
	
	@Test
	public void postNullPublicKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("Missing key encoding");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
				.setIdentifier(UUID.randomUUID().toString())
				.setSignature(ByteString.copyFrom(_firstSignature))
				.build());
	}

	@Test
	public void postInvalidMessageSize() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("Invalid Message Length provided: over 255 characters");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(INVALID_MESSAGE)
				.setIdentifier(UUID.randomUUID().toString())
				.setSignature(ByteString.copyFrom(_bigMessageSignature))
				.build());
	}

	@Test
	public void postNullSignature() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setIdentifier(UUID.randomUUID().toString())
				.setMessage(MESSAGE)
				.build());
	}

	@Test
	public void postInvalidSignature() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("Invalid Signature: Signature Could not be verified");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setIdentifier(UUID.randomUUID().toString())
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.build());
	}

}
