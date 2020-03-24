package dpas.server.service;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;

import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import com.google.protobuf.ByteString;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class PersistenceManagerTest {
	@Rule
	public ExpectedException exception = ExpectedException.none();
	
	private PublicKey _serverKey;
	
	private static final String encodedServerKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCcATE5p/ULOs4ZA3zl4LIGv8BAQEVM8OJF74mhUDOvd8kHybQod18GrsAW1J9htfqtqwZo6MQr7FzBpv/14b7USWRU8ae0ZlZMWUOo9KsWX7kvkbkaV86xnm0ez2ZDlvJH+n3a7NKoroLDVurbqnZEO0hXu8wsJZdjbf0LpGq59wIDAQAB";

	private static final String encodedKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCTYwRzEpPRUmWCrbY91oK0z75nTtiopu+qjpOnxH8mimb6jqURTNomHsbsB4xGO00GuBK58omAeKS2JEt7Fp5kj2GBqU3Sm/3PJXnkqoUVP3wIatleA25vtG/H9zo0wMYRHjRD/p67VdTcOI+iVXvLBRC9TUgK/nQC8rFSTcB8awIDAQAB";
	private static final String secondEncodedKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCg9dCJTjbki6HsswBebUUsVunayvP0WB4l8Wb/U4+41oG5HAALV5bJbff7XDcOYs6lPaR2+zUNm4X2RvSPap0x4S5/qlM72munFI36WtbQikjbu7J8q8/rd85QPat6IyFhoolT74pjyhK4flgq49MKQ5J3ucPEGkX9xtzXazklKwIDAQAB";


	private static final String firstIdentifier = "QyAbdOlghm0CBzzAlpvf6FjzkpmtbABL1e82/8IPlg4=";
	private static final String secondIdentifier = "8aFCYeCsgLBergGuzz7eG6V9Sc14lJV1n6VZyWDG1uQ=";
	
	@Before
	public void setup() throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] encoded = Base64.getDecoder().decode(encodedServerKey);
		_serverKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(encoded));
	}

	@After
	public void teardown() {

	}

	@Test
	public void testServerPersistence() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException,
			CommonDomainException, InvalidKeyException, SignatureException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_5.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);
		ServiceDPASPersistentImpl impl = manager.load();

		impl = manager.load();

		assertEquals(impl.getAnnouncements().get(firstIdentifier).getMessage(), "Message");
		assertEquals(impl.getAnnouncements().get(secondIdentifier).getMessage(),
				"Second Message");

		byte[] publicBytes = Base64.getDecoder().decode(encodedKey);
		byte[] publicBytes2 = Base64.getDecoder().decode(secondEncodedKey);

		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
		X509EncodedKeySpec keySpec2 = new X509EncodedKeySpec(publicBytes2);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(keySpec);
		PublicKey pubKey2 = keyFactory.generatePublic(keySpec2);

		assertArrayEquals(impl.getUsers().get(pubKey).getPublicKey().getEncoded(), pubKey.getEncoded());
		assertArrayEquals(impl.getUsers().get(pubKey2).getPublicKey().getEncoded(), pubKey2.getEncoded());

	}

	@Test
	public void invalidRegister() throws IOException, InterruptedException, InvalidKeySpecException,
			NoSuchAlgorithmException, CommonDomainException, InvalidKeyException, SignatureException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("no_operations_2.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		/* SERVER SETUP */
		ServiceDPASGrpc.ServiceDPASBlockingStub stub;
		final BindableService impl = manager.load();
		// Start server
		Server server = NettyServerBuilder.forPort(9000).addService(impl).build();
		server.start();

		final String host = "localhost";
		final int port = 9000;
		ManagedChannel channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		stub = ServiceDPASGrpc.newBlockingStub(channel);
		/* END SERVER SETUP */

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Public Key");
		try {
			stub.register(Contract.RegisterRequest.newBuilder().build());
		} finally {

			JsonArray jsonArray = manager.readSaveFile();
			assertEquals(0, jsonArray.size());

			// TEARDOWN
			channel.shutdownNow();
			server.shutdownNow();

			assertTrue(server.isShutdown());
			assertTrue(channel.isShutdown());
		}

	}

	@Test
	public void validRegister() throws IOException, NoSuchAlgorithmException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_4.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PublicKey pubKey = keygen.generateKeyPair().getPublic();
		String userName = "USERNAME";

		JsonArray jsonArray = manager.readSaveFile();

		JsonObject json = Json.createObjectBuilder().add("Type", "Register")
				.add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded())).add("User", userName)
				.build();

		manager.save(json);

		jsonArray = manager.readSaveFile();

		for (int i = jsonArray.size() - 1; i < jsonArray.size(); i++) {
			JsonObject operation = jsonArray.getJsonObject(i);
			assertEquals(operation.getString("Type"), "Register");
			assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
			assertEquals(operation.getString("User"), userName);
		}

	}

	@Test
	public void validVariousRegister() throws IOException, NoSuchAlgorithmException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_4.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PublicKey pubKey = keygen.generateKeyPair().getPublic();
		String userName = "USERNAME";

		JsonArray jsonArray = manager.readSaveFile();

		JsonObject json = Json.createObjectBuilder().add("Type", "Register")
				.add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded())).add("User", userName)
				.build();

		for (int i = 0; i < 5; ++i) {
			manager.save(json);
		}

		jsonArray = manager.readSaveFile();

		for (int i = jsonArray.size() - 5; i < jsonArray.size(); i++) {
			JsonObject operation = jsonArray.getJsonObject(i);
			assertEquals(operation.getString("Type"), "Register");
			assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
			assertEquals(operation.getString("User"), userName);
		}
	}

	@Test
	public void invalidPost() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
			InvalidKeySpecException, CommonDomainException, InterruptedException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_6.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		int sizeInitialJson = manager.readSaveFile().size();

		/* SERVER SETUP */
		ServiceDPASGrpc.ServiceDPASBlockingStub stub;
		BindableService impl = manager.load();
		// Start server
		Server server = NettyServerBuilder.forPort(9000).addService(impl).build();
		server.start();
		final String host = "localhost";
		final int port = 9000;
		ManagedChannel channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		stub = ServiceDPASGrpc.newBlockingStub(channel);
		/* END SERVER SETUP */

		String message = "MESSAGE";

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PrivateKey privateKey = keygen.generateKeyPair().getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		byte[] signature = sign.sign();

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Key Provided");

		try {
			stub.post(Contract.PostRequest.newBuilder().setMessage(message)
					.setSignature(ByteString.copyFrom(signature))
					.build());
		} finally {
			assertEquals(sizeInitialJson, manager.readSaveFile().size());
			// TEARDOWN
			channel.shutdownNow();
			server.shutdownNow();
			assertTrue(server.isShutdown());
			assertTrue(channel.isShutdown());
		}

	}

	@Test
	public void validPost() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_2.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		String message = "Hello World";

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PublicKey pubKey = keygen.generateKeyPair().getPublic();
		PrivateKey privateKey = keygen.generateKeyPair().getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		byte[] signature = sign.sign();
		String identifier = "a1s2d3f4g5h638j438j499j9j9jm";

		JsonObject json = Json.createObjectBuilder().add("Type", "Post")
				.add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
				.add("Signature", Base64.getEncoder().encodeToString(signature)).add("References", "null")
				.add("Identifier", identifier).add("Message", message).build();

		manager.save(json);

		JsonArray jsonArray = manager.readSaveFile();
		for (int i = jsonArray.size() - 1; i < jsonArray.size(); i++) {
			JsonObject operation = jsonArray.getJsonObject(i);
			assertEquals(operation.getString("Type"), "Post");
			assertEquals(operation.getString("Message"), message);
			assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
			assertEquals(operation.getString("Signature"), Base64.getEncoder().encodeToString(signature));
			assertEquals(operation.getString("References"), "null");
			assertEquals(operation.getString("Identifier"), identifier);
		}
	}

	@Test
	public void validVariousPost()
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_2.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		String message = "Hello World";

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PublicKey pubKey = keygen.generateKeyPair().getPublic();
		PrivateKey privateKey = keygen.generateKeyPair().getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		byte[] signature = sign.sign();
		String identifier = "a1s2d3f4g5h638j438j499j9j9jm";

		JsonObject json = Json.createObjectBuilder().add("Type", "Post")
				.add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
				.add("Signature", Base64.getEncoder().encodeToString(signature)).add("References", "null")
				.add("Identifier", identifier).add("Message", message).build();

		for (int i = 0; i < 5; ++i) {
			manager.save(json);
		}

		JsonArray jsonArray = manager.readSaveFile();
		for (int i = jsonArray.size() - 5; i < jsonArray.size(); i++) {
			JsonObject operation = jsonArray.getJsonObject(i);
			assertEquals(operation.getString("Type"), "Post");
			assertEquals(operation.getString("Message"), message);
			assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
			assertEquals(operation.getString("Signature"), Base64.getEncoder().encodeToString(signature));
			assertEquals(operation.getString("References"), "null");
			assertEquals(operation.getString("Identifier"), identifier);
		}
	}

	@Test
	public void invalidPostGeneral() throws IOException, InvalidKeyException, SignatureException,
			NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_7.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);
		int sizeInitialJson = manager.readSaveFile().size();

		/* SERVER SETUP */
		ServiceDPASGrpc.ServiceDPASBlockingStub stub;
		Server server;
		BindableService impl = manager.load();
		// Start server
		server = NettyServerBuilder.forPort(9000).addService(impl).build();
		server.start();
		final String host = "localhost";
		final int port = 9000;
		ManagedChannel channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		stub = ServiceDPASGrpc.newBlockingStub(channel);
		/* END SERVER SETUP */

		String message = "MESSAGE";

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PrivateKey privateKey = keygen.generateKeyPair().getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		byte[] signature = sign.sign();

		exception.expect(StatusRuntimeException.class);
		exception.expectMessage("INVALID_ARGUMENT: Invalid Key Provide");

		try {

			stub.postGeneral(Contract.PostRequest.newBuilder()
					.setMessage(message)
					.setSignature(ByteString.copyFrom(signature))
					.build());
		} finally {
			assertEquals(sizeInitialJson, manager.readSaveFile().size());
			// TEARDOWN
			server.shutdownNow();
			channel.shutdownNow();

			assertTrue(server.isShutdown());
			assertTrue(channel.isShutdown());
		}
	}

	@Test
	public void validPostGeneral()
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_3.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		String message = "Hello World";

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PublicKey pubKey = keygen.generateKeyPair().getPublic();
		PrivateKey privateKey = keygen.generateKeyPair().getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		byte[] signature = sign.sign();
		String identifier = "a1s2d3f4g5h6";

		JsonObject json = Json.createObjectBuilder().add("Type", "PostGeneral")
				.add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
				.add("Signature", Base64.getEncoder().encodeToString(signature)).add("References", "null")
				.add("Identifier", identifier).add("Message", message).build();

		manager.save(json);

		JsonArray jsonArray = manager.readSaveFile();
		for (int i = jsonArray.size() - 1; i < jsonArray.size(); i++) {
			JsonObject operation = jsonArray.getJsonObject(i);
			assertEquals(operation.getString("Type"), "PostGeneral");
			assertEquals(operation.getString("Message"), message);
			assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
			assertEquals(operation.getString("Signature"), Base64.getEncoder().encodeToString(signature));
			assertEquals(operation.getString("References"), "null");
			assertEquals(operation.getString("Identifier"), identifier);
		}
	}

	@Test
	public void validVariousPostGeneral()
			throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_2.json").getPath();
		PersistenceManager manager = new PersistenceManager(path, _serverKey);

		String message = "Hello World";

		KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
		keygen.initialize(1024);
		PublicKey pubKey = keygen.generateKeyPair().getPublic();
		PrivateKey privateKey = keygen.generateKeyPair().getPrivate();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privateKey);
		sign.update(message.getBytes());
		byte[] signature = sign.sign();
		String identifier = "a1s2d3f4g5h638j438j499j9j9jm";

		JsonObject json = Json.createObjectBuilder().add("Type", "PostGeneral")
				.add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
				.add("Signature", Base64.getEncoder().encodeToString(signature)).add("References", "null")
				.add("Identifier", identifier).add("Message", message).build();

		for (int i = 0; i < 5; ++i) {
			manager.save(json);
		}

		JsonArray jsonArray = manager.readSaveFile();
		for (int i = jsonArray.size() - 5; i < jsonArray.size(); i++) {
			JsonObject operation = jsonArray.getJsonObject(i);
			assertEquals(operation.getString("Type"), "PostGeneral");
			assertEquals(operation.getString("Message"), message);
			assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
			assertEquals(operation.getString("Signature"), Base64.getEncoder().encodeToString(signature));
			assertEquals(operation.getString("References"), "null");
			assertEquals(operation.getString("Identifier"), identifier);
		}
	}

	@Test(expected = JsonException.class)
	public void loadInvalidFile() throws IOException, SignatureException, CommonDomainException,
			InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("empty.json").getPath();

		PersistenceManager manager = new PersistenceManager(path, _serverKey);
		manager.load();
	}

	@Test
	public void loadNoOperationsFile() throws IOException, SignatureException, CommonDomainException,
			InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("no_operations.json").getPath();

		PersistenceManager manager = new PersistenceManager(path, _serverKey);
		ServiceDPASPersistentImpl impl = manager.load();
		assertEquals(impl._announcements.size(), 0);
		assertEquals(impl._users.size(), 0);
	}

	@Test
	public void loadGeneralTest() throws IOException, SignatureException, CommonDomainException,
			InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target.json").getPath();

		PersistenceManager manager = new PersistenceManager(path, _serverKey);
		ServiceDPASPersistentImpl impl = manager.load();
		assertEquals(impl._announcements.size(), 2);
		assertEquals(impl._users.size(), 2);
	}

	@Test
	public void loadGeneralTestWithSwap() throws IOException, SignatureException, CommonDomainException,
			InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
		ClassLoader classLoader = getClass().getClassLoader();
		String path = classLoader.getResource("valid_load_target_with_swap.json").getPath();

		PersistenceManager manager = new PersistenceManager(path, _serverKey);
		ServiceDPASPersistentImpl impl = manager.load();
		assertEquals(impl._announcements.size(), 2);
		assertEquals(impl._users.size(), 2);
	}

}
