package dpas.server.service;

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
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
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

    private static final String encodedKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn1g2uU4qXntakU5yEj61PDq0SnYH9S4LMvuKbF5w0fsRuliWyGBrKgFvnYxBPbs4PwgAbqBSQTUG9C5ZzgCIFlV+tWy5x4KxUF+ajLpQ+3SNUi9MyHiB05/usHYbMRfs4SawMLu4a7lVDACz2Ue4qpkaEUkd1gGcxz2a3COIgRhf8pIvzC0rpJzRE1YZks/gqFud5hFceOIhoZdpzgd4R24Ni7xIoPSWs3p1iprPLFK7V+9Aag5Wx81dP0I5PDlSw3bwFktotgExxj2xejV5APtFADtBl5W0zQxtoyUNH2Fa4HL+XYc3Unne5MyuveGDYGyNMgujjsW9OQaIaMJ2CCXZggqcX9cu+9JX4dh6uAEYsG80t6IQ8vEF/Q6JZCRE7FQS4OU4x8F/zaSrEBoL0BbWefwcNVemQSFr/hDoh3xEtL01DqblimXLqb24E0enqKNqOotpdUVm+/SWyBa9Nk9G3DWvNk+Y6jpeep6tbj2LLafIDJeNvDldtkaXwNSxzC4FFK4vIh0mEZ0gbscUtNHj9rQLCzoH8g3ZwoZy0B27pLMP8An7f0CNUmmaFuBiWtCjIThd3Gzov8NMX/ofrLMGtNzd7azAe1rQgYOUQIaiMJgIBzXfDpYWmu79gByR84eGmFSKMpfNyUzCuKSx3ih/PjF6UClIuUSiwcg5IbUCAwEAAQ==";
    private static final String secondEncodedKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnGFp8My6pu4RCvcj+zd9z22n97ZdUuBznwqxnGp6sVZrlxG62jV5yrR02b44ebwOuen3Ch5Jw+8XWAG7ZAKKyZfU7UP+VESQbMGxAv4Jp/j2uwwnIHAT2U9sRaP+BpobCAjkOXu2lsGNXXnoos3iE9+TnEM0JTTwpLy2yEqmScfP4c5A/6UpDJwHO8MaCqiscwVktB36lUY6rk5NaoK/XbJMOSHtocrjOGnrqFiUlIKt7tMb5PrP54owTanUenVI3BopXtAUTfl10YtiKnCwDOJt3uze47yHnS6pDk6+c+3DiJF1A7TxDr4WPCYqozN9QEfm3kxy6nT7VhngSjlUL4sDLi5X+PXtsyBBjKQ1xej+fYnbDJSRouhYqRiXgppxXaGRkctFJ3ZihXMzrzTQCj8jdrw0h++rFxbJgEsmVW4kpLT0TpZ9MvekXZTYkyuMIYF7u/ZSLoW8w18jbUd2FdEwzM85p2D1H/h1yQcLBQ8tMI7QnTlAu4zWPaqRzanIv5FGHyeqtWeTp1D1uMUIz6f5ugpJ+mEWprjEtHRuhk+R8wXmksTzm+tVIjGKHWsGjmiEizooZxMRm+PP4to7KZhY3YeTPIMXUjMutAKnfLSCSYbaCj5S5GJ6NQLYITeMEjByQS2Dg6/jWvQVSdGQ3WPS+HfsIKijQo4ZwGqfpsMCAwEAAQ==";


    private static final String firstIdentifier = "G6xX+YiQ/jiZrTM01r1LUbWCcFJhD5wTjeaJAovbvFA=";
    private static final String secondIdentifier = "/syDIMIqrhAvKY6KBssPvQN8g428b4aDLKX4dRR329A=";

    @After
    public void teardown() {

    }

    @Test
    public void testServerPersistence() throws IOException, GeneralSecurityException,
            CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_5.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();


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
    public void invalidRegister() throws IOException, GeneralSecurityException,
            CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("no_operations_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);

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

        PersistenceManager manager = new PersistenceManager(path);

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

        PersistenceManager manager = new PersistenceManager(path);

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
    public void invalidPost() throws IOException, GeneralSecurityException,
            CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_6.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);

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

        URL res = getClass().getClassLoader().getResource("valid_load_target_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();
        PersistenceManager manager = new PersistenceManager(path);

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

        URL res = getClass().getClassLoader().getResource("valid_load_target_2.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);

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
    public void invalidPostGeneral() throws IOException, GeneralSecurityException,
            CommonDomainException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_7.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
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

        PersistenceManager manager = new PersistenceManager(path);

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

        PersistenceManager manager = new PersistenceManager(path);

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
            GeneralSecurityException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("empty.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        manager.load();
    }

    @Test
    public void loadNoOperationsFile() throws IOException, CommonDomainException,
            GeneralSecurityException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("no_operations.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 0);
        assertEquals(impl._users.size(), 0);
    }

    @Test
    public void loadGeneralTest() throws IOException, CommonDomainException,
            GeneralSecurityException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 2);
        assertEquals(impl._users.size(), 2);
    }

    @Test
    public void loadGeneralTestWithSwap() throws IOException, CommonDomainException,
            GeneralSecurityException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_with_swap.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 2);
        assertEquals(impl._users.size(), 2);
    }

}
