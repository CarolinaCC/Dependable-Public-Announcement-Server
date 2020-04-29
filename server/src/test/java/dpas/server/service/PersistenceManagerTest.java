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
import org.junit.Ignore;
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
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import static org.junit.Assert.*;

@Ignore
public class PersistenceManagerTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final String encodedKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAnFf5LqH4eknmbAND50jZlYJtVvlRBXaGDjYKFvszcg/GQjwuUhOAq2VDd8kiGXYPne67cTKqR/STfEoJFZ+BJhOrZaAF2L7avSY9hNHjI4iOcbTctGapK4clqdS9AwGCLynmBHG8eEUWZWkoCPou/EaW+mCpGr/mdMWGvUwTnAXS5Ta3fyWlYVa9GAubqOziJurX7fSTB9kp3KvJ9XiY+2FP8hwnqvGnd498nwd/ishajuQGSZQtgjxdJkZz6PWyL+Ont7ON8LYKjV+5TYDebD91VQaQOUZQqoWvgOEMtjsfo+xRLD1f+++eCUFKIxBGVAKY8CNDF/fcNF5KqMqui85OtTmfHuARPNVeUeNh+qJFNVq20fYpYrbNGBIUA3Tl4bEDtuOSKWbxidizZzpQxO6tNqQk13Aq3YBHucIGT/PsnyfN1xwr9YW/U3m2XYZ6nRj6NW2ACy/Ke60qYshsbcj4iLMzupv9qpTP+u4rgSsN9Mrm+65ogQ8+E6kR8CL8GufA/hIBo3JxJCFtEpA+POLCUyJc5E5eODzWsiUAWuVki32Pp4AfqNtJrTzdKSQJnKs75Q6FSWO7Ha0yOQim1/3dLMr+IU5rJVGbpt0rhsu3TNGcletTd0QfCoSRdKjCMqTInFNJQfzoWLf7mIcImLRn5nEoZVd3GjYkv5ALRYUCAwEAAQ==";
    private static final String secondEncodedKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA8PClNkMmF06iYrYH7zydIcuZW1IjLGi0BZX/3i54/FhgfgAAyYdCKeQa6A+1qRJTvIbcs/VRj2LLqITeChm1GW5RJXgmI0iSPrKJ1mZf978qCn5cw57JSTePrDwvQFMZuD8ZOqeguZQQTbJJeNlz92qdds+vxZGIMo/s+jAEkdh1x1olPRDEMg4aBcRW9n8tjY6TLgnlLtbuRVn46sAArWrt5p9mTLmd/7gCKCSiqlUgLFq45PSwGJVA+AkBvwotDEivZtQSNKR35wN8PB1PpqlcG0tVP5F+DES5I6KVmV+O7GJUL+7+LRE3gLPVBIDB9dWfsVISK61WHtdST+0ywtx552VyNHSXqp7gvpRl55LW49XhV6EwcRA14HcRKyvSZJBT4TcsYHelAuXumbrFuCFJbhg1+QM4Mq3Wv0qsrnSeXLRgB8NFg+kjUtRhFwWmmJdP+PfRQB9bRqlsrkNWy6SnRu8hnSr9YfHRI0SNcqCzdAgvb+47cYidCG6rdawheDTP0LeptXQGl4yTJbizcIrJ1g0q7+VeNrOyaghsrdHAKypbiW23QZZwC2s3aADLjYgvzNN87pEl/OEyHoEWQxgt9lHQSMzCW3BRXWWBhAKF8eT0BQ4kuBh9b6LxMsSJyijWzwraD1lYPDNCUqD9KZ/ixWcoiC7xwzt81oPJkz0CAwEAAQ==";


    private static final String firstIdentifier = "Bt1cXgVRitM/V3xfw1r17GUwJsI5FBocbmnXdmFEtIQ=";
    private static final String secondIdentifier = "IaEg3rilltMWOBWMMitk0Wv2gF3LIXcHUqXoOQc8tpk=";

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
            stub.post(Contract.Announcement.newBuilder().setMessage(message)
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

            stub.postGeneral(Contract.Announcement.newBuilder()
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
        assertEquals(impl.announcements.size(), 0);
        assertEquals(impl.users.size(), 0);
    }

    @Test
    public void loadGeneralTest() throws IOException, CommonDomainException,
            GeneralSecurityException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl.announcements.size(), 2);
        assertEquals(impl.users.size(), 2);
    }

    @Test
    public void loadGeneralTestWithSwap() throws IOException, CommonDomainException,
            GeneralSecurityException, URISyntaxException {

        URL res = getClass().getClassLoader().getResource("valid_load_target_with_swap.json");
        File file = Paths.get(res.toURI()).toFile();
        String path = file.getAbsolutePath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl.announcements.size(), 2);
        assertEquals(impl.users.size(), 2);
    }

}
