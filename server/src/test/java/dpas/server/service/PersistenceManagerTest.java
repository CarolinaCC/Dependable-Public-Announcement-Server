package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
import dpas.server.service.ServiceDPASPersistentImpl;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import org.junit.*;
import org.junit.rules.ExpectedException;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonException;
import javax.json.JsonObject;
import java.io.File;
import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.*;

public class PersistenceManagerTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private PublicKey _serverKey;

    private static final String encodedServerKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCjjcgcWE6gIo11rgDwn5Al1P/U68HV6aTvabmmDzhb0xngRKbqxplMtH58QRiq8VerruCuFccmFXtsl505SvgimC9s1QmEpyuXoACYiirlPJPhSlrrNBk2dgSo9lDAW3iAmm2jrnyuOjEnkjkSybok4lNsV9UjPwCtixs9wj3dvwIDAQAB";
    private static final String encodedKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCFtJcLhRw+6TkWS1VKAHjiOvtxF9giZrKqS+wc9J4aqrzIduyhljuGByAWMQ3uG3lvsTF/ibmIvuHtsPmjT2lk+kW9h63W+iREng98boLij5LUttG7jAN7gEfkpqSBJlHrUmJNk0tpbo9bDCZW7UlpyF9Z1dbghFF+1if+6+1viwIDAQAB";
    private static final String secondEncodedKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCF9x8XZWs8SDgtCk0NQR3wiROsstV6iB+PPQTslRoZPOo/2hPjGw/8s0lBbCglJu+QEh6A6PhxNJcCIf5jsu2f4RkqmB2/giqfJj05AN/ToUsyiBPHAk/rBDJPQjmLryyfCO47UKai3YC5Cdwc0rZ9M2F97hFYvIS3OGIL6DteMwIDAQAB";


    private static final String firstIdentifier = "f8cHn6BTMtPv3JpsdYsiOxUP3o3Tk8ydPSGEKDAX3E0=";
    private static final String secondIdentifier = "x9rTI230HpUf8JCDp9s8MEdtFBGOkfKN3mBuk5LVe7Y=";

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
            CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_5.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

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
    public void invalidRegister() throws IOException, InvalidKeySpecException,
            NoSuchAlgorithmException, CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("no_operations_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

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
    public void validRegister() throws IOException, NoSuchAlgorithmException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_4.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        PublicKey pubKey = keygen.generateKeyPair().getPublic();
        String userName = "USERNAME";

        JsonObject json = Json.createObjectBuilder().add("Type", "Register")
                .add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded())).add("User", userName)
                .build();

        manager.save(json);

        JsonArray jsonArray = manager.readSaveFile();

        for (int i = jsonArray.size() - 1; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            assertEquals(operation.getString("Type"), "Register");
            assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            assertEquals(operation.getString("User"), userName);
        }

    }

    @Test
    public void validVariousRegister() throws IOException, NoSuchAlgorithmException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_4.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
        PublicKey pubKey = keygen.generateKeyPair().getPublic();
        String userName = "USERNAME";

        JsonObject json = Json.createObjectBuilder().add("Type", "Register")
                .add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded())).add("User", userName)
                .build();

        for (int i = 0; i < 5; ++i) {
            manager.save(json);
        }

        JsonArray jsonArray = manager.readSaveFile();

        for (int i = jsonArray.size() - 5; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            assertEquals(operation.getString("Type"), "Register");
            assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
            assertEquals(operation.getString("User"), userName);
        }
    }

    @Test
    public void invalidPost() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException,
            InvalidKeySpecException, CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_6.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

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
        keygen.initialize(4096);
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
    public void validPost() throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, URISyntaxException {

        ClassLoader classLoader = getClass().getClassLoader();

        URL res = getClass().getClassLoader().getResource("valid_load_target_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();
        PersistenceManager manager = new PersistenceManager(path, _serverKey);

        String message = "Hello World";

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
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
            throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, URISyntaxException {

        ClassLoader classLoader = getClass().getClassLoader();

        URL res = getClass().getClassLoader().getResource("valid_load_target_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);

        String message = "Hello World";

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
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
            NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException, URISyntaxException {

        ClassLoader classLoader = getClass().getClassLoader();

        URL res = getClass().getClassLoader().getResource("valid_load_target_7.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

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
        keygen.initialize(4096);
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
            throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_3.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);

        String message = "Hello World";

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
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
            throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);

        String message = "Hello World";

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(4096);
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
    public void loadInvalidFile() throws IOException, CommonDomainException,
            InvalidKeySpecException, NoSuchAlgorithmException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("empty.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);
        manager.load();
    }

    @Test
    public void loadNoOperationsFile() throws IOException, CommonDomainException,
            InvalidKeySpecException, NoSuchAlgorithmException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("no_operations.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 0);
        assertEquals(impl._users.size(), 0);
    }

    @Test
    public void loadGeneralTest() throws IOException, CommonDomainException,
            InvalidKeySpecException, NoSuchAlgorithmException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 2);
        assertEquals(impl._users.size(), 2);
    }

    @Test
    public void loadGeneralTestWithSwap() throws IOException, CommonDomainException,
            InvalidKeySpecException, NoSuchAlgorithmException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_with_swap.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path, _serverKey);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 2);
        assertEquals(impl._users.size(), 2);
    }

}
