package dpas.server.service;

import static org.junit.Assert.assertEquals;

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
import java.util.List;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.common.domain.Announcement;
import dpas.common.domain.User;
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

	private final static String USER_NAME = "USER";
	private final static String NON_REGISTERED_USER = "USER2";

	private PublicKey _publicKey;
	private User _user;

	private byte[] _signature;
	private byte[] _signature2;

	private final String MESSAGE = "Message to sign";
	private final String SECOND_MESSAGE = "Second message to sign";
	private ArrayList<Announcement> _references = null;

	@Before
	public void setup() throws IOException, NoSuchAlgorithmException, NullPublicKeyException, NullUsernameException,
			NullUserException, NullMessageException, InvalidMessageSizeException, NullSignatureException,
			SignatureException, NullAnnouncementException, InvalidKeyException, InvalidSignatureException,
			InvalidUserException {

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		_publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(MESSAGE.getBytes());
		_signature = sign.sign();

		Signature sign2 = Signature.getInstance("SHA256withRSA");
		sign2.initSign(privateKey);
		sign.update(SECOND_MESSAGE.getBytes());
		_signature2 = sign.sign();

		_user = new User(_publicKey);

		Announcement announcement = new Announcement(_signature, _user, MESSAGE, _references);
		_user.getUserBoard().post(announcement);

		final BindableService impl = new ServiceDPASImpl();

		// Start server
		_server = NettyServerBuilder.forPort(9000).addService(impl).build();
		_server.start();

		final String host = "localhost";
		final int port = 9000;
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel).withMaxInboundMessageSize(1024 * 1024 * 1024)
				.withMaxOutboundMessageSize(1024 * 1024 * 1024);

		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());

		_stub.post(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_signature))
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());

		_stub.post(Contract.PostRequest.newBuilder()
				.setMessage(SECOND_MESSAGE)
				.setSignature(ByteString.copyFrom(_signature2))
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
				.setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
				.setNumber(0)
				.build());
		
		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);

		assertEquals(announcementsGRPC.get(1).getMessage(), SECOND_MESSAGE);
		assertEquals(announcementsGRPC.get(1).getReferencesList().size(), 0);

	}

	@Test
	public void readSuccessAll() {

		Contract.ReadReply reply = _stub.read(
				Contract.ReadRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
				.setNumber(2)
				.build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);

		assertEquals(announcementsGRPC.get(1).getMessage(), SECOND_MESSAGE);
		assertEquals(announcementsGRPC.get(1).getReferencesList().size(), 0);

	}

	@Test
	public void readSuccess() {

		var reply = _stub.read(Contract.ReadRequest.newBuilder()
						.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
						.setNumber(1)
						.build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.get(0).getMessage(), SECOND_MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);

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