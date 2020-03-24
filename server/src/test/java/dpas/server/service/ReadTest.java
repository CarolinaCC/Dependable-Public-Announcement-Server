package dpas.server.service;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidMessageSizeException;
import dpas.common.domain.exception.InvalidSignatureException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullMessageException;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullSignatureException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class ReadTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
	private Server _server;
	private ManagedChannel _channel;

	private PublicKey _serverKey;
	private PublicKey _publicKey;
	private PrivateKey _privateKey;

	private byte[] _signature;
	private byte[] _signature2;
	
	private String _identifier;
	private String _identifier2;

	private static final String MESSAGE = "Message to sign";
	private static final String SECOND_MESSAGE = "Second message to sign";
	
	private static final String host = "localhost";
	private static final int port = 9000;

	@Before
	public void setup() throws IOException, NoSuchAlgorithmException, CommonDomainException, InvalidKeyException, SignatureException {
		// Keys
		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		
		KeyPair keyPair = keygen.generateKeyPair();
		_publicKey = keyPair.getPublic();
		_privateKey = keyPair.getPrivate();
		
		keyPair = keygen.generateKeyPair();
		_serverKey = keyPair.getPublic();

		//Identifiers
		_identifier =UUID.randomUUID().toString();
		_identifier2 =UUID.randomUUID().toString();

		//Signatures
		_signature = Announcement.generateSignature(_privateKey, MESSAGE, _identifier, null, Base64.getEncoder().encodeToString(_publicKey.getEncoded()));
		_signature2 = Announcement.generateSignature(_privateKey, SECOND_MESSAGE, _identifier2, null, Base64.getEncoder().encodeToString(_publicKey.getEncoded()));
		
		//Start Server
		final BindableService impl = new ServiceDPASImpl(_serverKey);
		_server = NettyServerBuilder.forPort(port).addService(impl).build();
		_server.start();

		//Connect to Server
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

		// Register User
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());

		// Posts to Read
		_stub.post(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_signature))
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.setIdentifier(_identifier)
				.build());
		_stub.post(Contract.PostRequest.newBuilder()
				.setMessage(SECOND_MESSAGE)
				.setSignature(ByteString.copyFrom(_signature2))
				.setIdentifier(_identifier2)
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());
	}

	@After
	public void teardown() {

		_server.shutdown();
		_channel.shutdown();
	}

	@Test
	public void readSuccessAllWith0() {

		Contract.ReadReply reply = _stub.read(
				Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.setNumber(0)
				.build());
		
		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();
		
		assertEquals(announcementsGRPC.size(), 2);
		
		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(0).getIdentifier(), _identifier);
		assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);

		assertEquals(announcementsGRPC.get(1).getMessage(), SECOND_MESSAGE);
		assertEquals(announcementsGRPC.get(1).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(1).getIdentifier(), _identifier2);
		assertArrayEquals(announcementsGRPC.get(1).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(1).getSignature().toByteArray(), _signature2);
	}

	@Test
	public void readSuccessAll() {

		Contract.ReadReply reply = _stub.read(
				Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.setNumber(2)
				.build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.size(), 2);
		
		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(0).getIdentifier(), _identifier);
		assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);

		assertEquals(announcementsGRPC.get(1).getMessage(), SECOND_MESSAGE);
		assertEquals(announcementsGRPC.get(1).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(1).getIdentifier(), _identifier2);
		assertArrayEquals(announcementsGRPC.get(1).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(1).getSignature().toByteArray(), _signature2);
	}

	@Test
	public void readSuccess() {

		var reply = _stub.read(Contract.ReadRequest.newBuilder()
						.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
						.setNumber(1)
						.build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.size(), 1);
		
		assertEquals(announcementsGRPC.get(0).getMessage(), SECOND_MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(0).getIdentifier(), _identifier2);
		assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature2);
	}

	@Test
	public void readInvalidNumberOfPosts() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid number of posts to read: number cannot be negative");

		_stub.read(Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.setNumber(-1)
				.build());
	}

	@Test
	public void readNullKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");

		_stub.read(Contract.ReadRequest.newBuilder().setNumber(0).build());
	}

	@Test
	public void readEmptyKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Missing key encoding");

		_stub.read(Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(new byte[0]))
				.setNumber(0)
				.build());
	}

	@Test
	public void readArbitraryKey() {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: invalid key format");

		_stub.read(Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(new byte[] { 12, 2, 12, 5 }))
				.setNumber(0)
				.build());
	}

	@Test
	public void readWrongAlgorithmKey() throws NoSuchAlgorithmException {

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: java.security.InvalidKeyException: Invalid RSA public key");

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();

		_stub.read(Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
				.setNumber(0)
				.build());
	}

	@Test
	public void readUserNotRegistered() throws NoSuchAlgorithmException {
		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: User with public key does not exist");

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();

		_stub.read(Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
				.setNumber(0)
				.build());

	}

}