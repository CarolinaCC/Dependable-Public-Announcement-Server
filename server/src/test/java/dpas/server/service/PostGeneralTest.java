package dpas.server.service;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;

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

public class PostGeneralTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

	private Server _server;
	private PublicKey _serverKey;
	
	private PublicKey _firstPublicKey;
	private PublicKey _secondPublicKey;
	
	private PrivateKey _firstPrivateKey;
	private PrivateKey _secondPrivateKey;
	

	
	private byte[] _firstSignature;
	private byte[] _secondSignature;
	private byte[] _secondSignatureWithRef;
	private byte[] _signatureForSameId;
	private byte[] _bigMessageSignature;

	private ManagedChannel _channel;

	private static final String MESSAGE = "Message";
	private static final String SECOND_MESSAGE = "Second Message";
	private static final String INVALID_MESSAGE = StringUtils.repeat("ThisMessageisInvalid", "", 15);
	
	@Before
	public void setup() throws IOException, CommonDomainException, NoSuchAlgorithmException {

		// KeyPairs
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		keyPair = keygen.generateKeyPair();
		_serverKey = keyPair.getPublic();
		keygen.generateKeyPair();
		keyPair = keygen.generateKeyPair();
		_firstPublicKey = keyPair.getPublic();
		_firstPrivateKey = keyPair.getPrivate();
		keyPair = keygen.generateKeyPair();
		_secondPublicKey = keyPair.getPublic();
		_secondPrivateKey = keyPair.getPrivate();
		
		//Signatures
		_firstSignature = Announcement.generateSignature(_firstPrivateKey, MESSAGE,
				new ArrayList<>(), "DPAS-GENERAL-BOARD");
		
		_secondSignature = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
				new ArrayList<>(), "DPAS-GENERAL-BOARD");
		
		_signatureForSameId = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
				new ArrayList<>(), "DPAS-GENERAL-BOARD");

		
		_bigMessageSignature = Announcement.generateSignature(_firstPrivateKey, INVALID_MESSAGE,
				new ArrayList<>(), "DPAS-GENERAL-BOARD");

		
		// Start server
		final BindableService impl = new ServiceDPASImpl(_serverKey);
		_server = NettyServerBuilder.forPort(9000).addService(impl).build();
		_server.start();

		// Connect to server
		final String host = "localhost";
		final int port = 9000;
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

		// Register Users
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded())).build());
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
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_firstSignature))
				.build());
	}

	@Test
	public void twoPostsSuccess() {
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
				.build());

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE).setSignature(ByteString.copyFrom(_secondSignature))
				.build());
	}

	@Test
	public void twoPostsWithReference() throws CommonDomainException {
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE).setSignature(ByteString.copyFrom(_firstSignature))
				.build());

		var firstIdentifier = _stub.readGeneral(Contract.ReadRequest
				.newBuilder()
				.setNumber(1)
				.build())
				.getAnnouncements(0)
				.getHash();

		_secondSignatureWithRef = Announcement.generateSignature(_secondPrivateKey, SECOND_MESSAGE,
				Collections.singletonList(firstIdentifier), "DPAS-GENERAL-BOARD");


		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_secondPublicKey.getEncoded()))
				.setMessage(SECOND_MESSAGE)
				.addReferences(firstIdentifier)
				.setSignature(ByteString.copyFrom(_secondSignatureWithRef))
				.build());
	}

	
	@Test
	public void postNullPublicKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("Missing key encoding");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
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
				.setSignature(ByteString.copyFrom(_bigMessageSignature))
				.build());
	}

	@Test
	public void postNullSignature() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Signature");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.build());
	}

	@Test
	public void postInvalidSignature() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("Invalid Signature: Signature Could not be verified");

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_firstPublicKey.getEncoded()))
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_secondSignature))
				.build());
	}

}
