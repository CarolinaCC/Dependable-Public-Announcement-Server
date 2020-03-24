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
import java.security.Signature;
import java.security.SignatureException;
import java.util.List;
import java.util.UUID;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.common.domain.Announcement;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class ReadGeneralTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private Server _server;
	private PublicKey _serverKey;
	
	private ManagedChannel _channel;
	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
	
	private PublicKey _publicKey;
	private PrivateKey _privateKey;
	
	private byte[] _signature;
	private String _identifier;
	
	private static final String host = "localhost";
	private static final int port = 9000;
	

	private static final String MESSAGE = "Message to sign";

	@Before
	public void setup() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		
		KeyPair keyPair = keygen.generateKeyPair();
		_publicKey = keyPair.getPublic();
		_privateKey = keyPair.getPrivate();
		
		keygen.generateKeyPair();
		_serverKey = keyPair.getPublic();
		
		_identifier = UUID.randomUUID().toString();
		_signature = Announcement.generateSignature(_privateKey, MESSAGE, _identifier, null, _serverKey);
		
		// Start Server
		final BindableService impl = new ServiceDPASImpl(_serverKey);
		_server = NettyServerBuilder.forPort(port).addService(impl).build();
		_server.start();
		
		// Connect to Server
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

		// Register User
		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());
		
		// Create Post To Read
		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_signature))
				.setIdentifier(_identifier)
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());
	}

	@After
	public void tearDown() {

		_server.shutdown();
		_channel.shutdown();
	}

	@Test
	public void readSuccessAllWith0() {

		Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(0).build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.size(), 1);
		
		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(0).getIdentifier(), _identifier);
		assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);
	}

	@Test
	public void readSuccessAll() {
		Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(3).build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.size(), 1);
		
		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(0).getIdentifier(), _identifier);
		assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);
	}

	@Test
	public void readSuccess() {

		Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(1).build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.size(), 1);
		
		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
		assertEquals(announcementsGRPC.get(0).getIdentifier(), _identifier);
		assertArrayEquals(announcementsGRPC.get(0).getPublicKey().toByteArray(), _publicKey.getEncoded());
		assertArrayEquals(announcementsGRPC.get(0).getSignature().toByteArray(), _signature);
	}

	@Test
	public void readInvalidNumberOfPosts() {

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid number of posts to read: number cannot be negative");

		_stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(-1).build());
	}

}
