package dpas.server.service;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;

import org.apache.commons.lang3.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class PostTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

	private Server _server;
	private PublicKey _serverKey;
	
	private PublicKey _firstPublicKey;
	private PublicKey _secondPublicKey;
	private PublicKey _thirdPublicKey;

	private PrivateKey _firstPrivateKey;
	private PrivateKey _secondPrivateKey;
	private PrivateKey _thirdPrivateKey;
	
	private String _firstIdentifier;
	private String _secondIdentifier;
	
	private byte[] _firstSignature;
	private byte[] _secondSignature;
	private byte[] _secondSignatureWithRef;
	private byte[] _signatureForSameId;
	private byte[] _bigMessageSignature;

	private String _invalidReference;

	private ManagedChannel _channel;

	private static final String MESSAGE = "Message";
	private static final String SECOND_MESSAGE = "Second Message";
	private static final String INVALID_MESSAGE = StringUtils.repeat("ThisMessageisInvalid", "", 15);	

	private static final String host = "localhost";
	private static final int port = 9000;
	
	@Before
	public void setup() throws IOException, NoSuchAlgorithmException, CommonDomainException {

		// Identifiers
		_firstIdentifier = UUID.randomUUID().toString();
		_secondIdentifier = UUID.randomUUID().toString();

		
		// Keys
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		
		KeyPair keyPair = keygen.generateKeyPair();
		_firstPublicKey = keyPair.getPublic();
		_firstPrivateKey = keyPair.getPrivate();
		
		keyPair = keygen.generateKeyPair();
		_secondPublicKey = keyPair.getPublic();
		_secondPrivateKey = keyPair.getPrivate();
		
		keyPair = keygen.generateKeyPair();
		_thirdPublicKey = keyPair.getPublic();
		_thirdPrivateKey = keyPair.getPrivate();
		
		keyPair = keygen.generateKeyPair();
		_serverKey = keyPair.getPublic();
		
		// References
		_invalidReference = "";
		
	
		// Signatures
		_firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE, 
				_firstIdentifier, new ArrayList<>(), _firstPublicKey);

		_secondSignature = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE, 
				_secondIdentifier, new ArrayList<>(), _secondPublicKey);

		_secondSignatureWithRef = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE, 
				_secondIdentifier, Collections.singletonList(_firstIdentifier), _secondPublicKey);
		
		_signatureForSameId = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE, 
				_firstIdentifier, new ArrayList<>(), _secondPublicKey);
		
		_bigMessageSignature = Announcement.generateSignature(_firstPrivateKey, INVALID_MESSAGE, 
				_firstIdentifier, new ArrayList<>(), _firstPublicKey);
		
		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target.json").getPath();

		final BindableService impl = new ServiceDPASImpl(_serverKey);
		_server = NettyServerBuilder.forPort(port).addService(impl).build();
		_server.start();

		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

		//Register Users
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.build());
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
		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(_firstIdentifier)
				.build());
	}

	@Test
	public void twoPostsSuccess() {
		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(_firstIdentifier)
				.build());

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.setIdentifier(_secondIdentifier)
				.build());
	}

	@Test
	public void twoPostsValidReference() {
		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(_firstIdentifier)
				.build());

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.addReferences(_firstIdentifier)
				.setSignature(ByteString.copyFrom(_secondSignatureWithRef))
				.setIdentifier(_secondIdentifier)
				.build());
	}

	@Test
	public void twoPostsInvalidReference() {
		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(_firstIdentifier)
				.build());

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Reference: reference provided does not exist");

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.addReferences(_invalidReference)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.setIdentifier(_secondIdentifier)
				.build());
	}

	@Test
	public void twoPostsSameIdentifier() {
		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(_firstIdentifier)
				.build());

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Post Identifier Already Exists");

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.setSignature(ByteString.copyFrom(_signatureForSameId))
				.setIdentifier(_firstIdentifier)
				.build());
	}
	
	@Test
	public void postNullPublicKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");

		_stub.post(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.setIdentifier(_firstIdentifier)
				.build());
	}

	@Test
	public void postInvalidMessageSize() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Message");

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(INVALID_MESSAGE)
				.setSignature(ByteString.copyFrom(_bigMessageSignature))
				.setIdentifier(_firstIdentifier)
				.build());
	}

	@Test
	public void postNullSignature() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setIdentifier(_firstIdentifier)
				.setMessage(MESSAGE)
				.build());
	}

	@Test
	public void postInvalidSignature() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

		_stub.post(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.setIdentifier(_firstIdentifier)
				.build());
	}
}