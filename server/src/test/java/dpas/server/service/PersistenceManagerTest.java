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

public class PersistenceManagerTest {
    @Rule
    public ExpectedException exception = ExpectedException.none();

    private static final String encodedKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAm0pucFHoSc2xE8Bt56XmXEW8Dk+zYTKj3V9D4IgpOuJ+idtvEe7isEVUQ4CmNbRzmXMtk4O1r4289T9RsXKKWxMki8wQpgvkE6Y04es2orgW2CPwkfLdFVo+K5SXTDh69Bc0yQnSfuWc539nPIzSzuaysSfEeS+gBlUM5YnalYnILT7c7SeZyIx4cLi43xT1bb5AGew2D3D8mj+8WJ8/cKOK2bwMlcmJWCtDycf046qaLEmoYR9qUnLiuQD5iSsTQAOlsLTigPTwhnhCj1kQXeL6yGWriPfAS1Fb/EgK+xqxr0EUnh18w9ND1ha2aB23HNhJfQTzJ3zw+gQjLequepm4oELLAFjWcKo5NDjQdthbb3rgK6vNc/CEYx2O2AOeR0FqiFjrch7v4nMM7sBxscTW6NL96Rij86MQeAjcQ7qOwRtCka45uDPJ9VJDJQhw56i5XxYvP/w9vkqcf139YRdhy/Evco2iiLg+seuaARO6Oc7RlOcEvqaPodF7Rl212lbPMm+sRlg3EPWS0R6xzyy64wTx/uePIDOTXX/hBOqC14E4kDg89bMKPz7xEEym4jD2ibJcb3AdXCwOOMkYInMZ3TRZsklvu5E5kym+M1B7QLKE7Ca12QLQOLk9XKKpfXnyLRWlK1BLCMv942IOIWDFFf1rIOsmV0+uUMu6edkCAwEAAQ==";
    private static final String secondEncodedKey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlumvR5IowsiSVlsRa9qpdm5Jih+DladYCwl2xX5+0/sqocuts7YQsYIMB7km0xSTu1npKa743az9lLTWXK3sG6bh+/uFPnfCmqAesBb8X/70Xms53RR/L4RNHsnBBt51f0DVEMfqKK5LgN/U83HjUef+Gqxd12CLdjNWjonBu4lzN7O9y4cZmSo+QVW5IWWQiSA92h9yIv4qbJZ5VUbyrVWPdjP5FLNlIpZo0mV0lDcvVaUZ5oaKcZr84iIzctZe4yizhYroqHRhtO2Bqj5mt22ghHnrQtVoAjdYkbaayoAmz4Kps/G2MgwboA1Prg4sT8a578Gi3qo5kw741Q5KNmfwMXUZAIEDdWd7ZRudBv8dtnvlaooka5VX6JHfKH2W3nLvCHexp2yOQN7KjIxZxFx1O8i2OA8VXuD+wkC+5Qnhvez8mUEf5WOiI6LDw1hjmNbOH+KcIe3fsNe3+FAjzvsTiWblIcoWJlPAZccu+RrfULdtrUTVn39ox4EePpGKY6+eORrcdG5QVjIhqQ2BNNrEcwSmXCPkMXynkRjL07wyDMOKlCzRanNruYT3I72mK/paF0mb78V7nqUanEDbh6pZYR4162J/S4wMt5GNXI1xDgW20Ywo+YeL7oOxfdwjIHpylixYnKAq/RvOIjDr6An40iJvuaEAB+dZ2iOobf0CAwEAAQ==";


    private static final String firstIdentifier = "TMGlYr5opq5U1RJkYw+OHzHAFUrUhmLwUzV8sBwH4Myhtufh6T+xvNkh1prPDlrOHoNhKNgCbjNJNSrd9giyYNn33EyWmk1BXw9Dz0ugftcpi+Ey3dyEvxRncjcVd5gN276vLy0d+xDRpLifUzLWwWOY4QKBk+r5slSbRd+xIjsQcEHAuG4ET5wKf7AYpPFGuaqxoydzL5PqBuvMG6Vhu8yFkzNQsZzvjbWujncyqftyCrWdqBdZN/eGSO8Sa++FNsSa4lHyDGgG6K28OdxD+E7ncge+3ECwj+LwKOfuzciV262Hh38H3ZeENSwfEaGb8qsLeFPUAY2ogyeFTTqZWc45+3ykXes5b9tE5a1YZ1aKx/frVn2lY8BevX9C0w+MSVij85MV3t9EbC3d6Ap6HIguzIgFbP5n+ZmrV7wRbcTW2z8pQp7COzjAjS4TXV0xRYZyqRLvu7KK3+ndBuUyn3WpaOO/Gh6kH4/LKC1N7Nzu2PEyivSJ3MPbpFU9Srg+CrVc+ZnO6UjwWtjoZ834/5K9L5mOBPPsGtlE9JsNCqoqmeC5K4BsekvPcIsFV0Gwit3s+psoflQHuuH9/Ec/OT4oHmEtgcKmWH/iltL9jMK4sdstTAQzHOqXQHxsX+jDt73vEKU0sxhm4kHcyzq5evuGUvCiAfMCAKAPqs9jNcQ=";
    private static final String secondIdentifier = "gr4b3A++aehOU+OUG7sKMouliASadWp+ZwsxjZJRe21GvjmS695zc6qrlJ6j4R62IFtK8FpQa4Ou2wzhxhf1cj+Lr3uL4ZeXiDVZPseTcTO6+PtafVrFGiMTz7dcX24XKEj4PgIxH9lSLgrHNwpvWmxo/J0jh2AnNHISWDaDXQQuX9dcF2hmEAo3+7e7klVlDJwomMPQBLXJr0bTEgb1nBXglovscCohzRPn3/yrMxHlFzN59OzB6qCVBNwCAYiF1loHK5x9M3aoF8ViWmjlK07ILmSJ/aXOdDYyizWND6XjJeR4KMffXJMrYkKFEnn9rCG/xRcXsaZBGgn8dvsEVOEto4AltEDXVGLCdqaY0x8uskoZzDjmbOqEK2yDzvA+BbStkwb6qmTDUKw6MlI9DRiF4/kJLmD4PxEg0w6IWtgzwpGtHMUxth38nzD+0hop/BsnALaNF1606K5DjacM+uZk02Bv1EedkAaLsKcxdjr/iAXfSzeUrEYw/R6tMQsGI1lmJtCboAWxROHtKDFbiLcQ/R1DlT9M5zxuzok1dPTlNJGMjHXb5JBInmmfxG2fAexrJTb0d5nfRrdf/7e+lIBj2AeomS6kzqRVfk210/x8wHsJV4IeZ9d7qbewjXjNbC28PHonrFJMS2fwhlj04ON1RjOV0y9fA6lquy7drI0=";

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
