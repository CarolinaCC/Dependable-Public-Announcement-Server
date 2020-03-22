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
import java.util.List;

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

public class ReadGeneralTest {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;
	private Server _server;
	private ManagedChannel _channel;
	private PublicKey _publicKey;

	private static final String USER_NAME = "USER";
	private static final String MESSAGE = "Message to sign";

	@Before
	public void setup() throws IOException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		KeyPair keyPair = keygen.generateKeyPair();
		_publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(MESSAGE.getBytes());
		byte[] _signature = sign.sign();

		final BindableService impl = new ServiceDPASImpl();

		// Start server
		_server = NettyServerBuilder.forPort(9000).addService(impl).build();
		_server.start();

		final String host = "localhost";
		final int port = 9000;
		_channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);

		_stub.register(Contract.RegisterRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(_publicKey.getEncoded()))
				.build());

		_stub.postGeneral(Contract.PostRequest.newBuilder()
				.setMessage(MESSAGE)
				.setSignature(ByteString.copyFrom(_signature))
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

		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
	}

	@Test
	public void readSuccessAll() {
		Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(3).build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);
	}

	@Test
	public void readSuccess() {

		Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(1).build());

		List<Contract.Announcement> announcementsGRPC = reply.getAnnouncementsList();

		assertEquals(announcementsGRPC.get(0).getMessage(), MESSAGE);
		assertEquals(announcementsGRPC.get(0).getReferencesList().size(), 0);

	}

	@Test
	public void readInvalidNumberOfPosts() {

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid number of posts to read: number cannot be negative");

		_stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(-1).build());
	}

}
