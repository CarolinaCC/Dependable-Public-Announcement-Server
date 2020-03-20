package dpas.server.service;

import com.google.protobuf.ByteString;
import com.google.protobuf.Empty;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.stub.StreamObserver;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.json.*;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.UUID;

import static org.junit.Assert.assertEquals;

public class PersistenceManagerTest {

   /* Create Server from load. Shutdown. Start again. See if state persists.

    Register, see if file has been updated

    Post, see if file has been updated.

    PostGeneral, see if file has been updated.*/

    private Server _server;
    private ManagedChannel _channel;
    private ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

    @Before
    public void setup() throws IOException {

    }

    @After
    public void teardown() {

    }

    @Test
    public void testServerPersistence() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException,
            CommonDomainException, InvalidKeyException, SignatureException {

        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("valid_load_target_5.json").getPath();
        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();

        impl = null;
        impl = manager.load();

        assertEquals(impl.getAnnouncements().get("e248b5e6-b27e-47b9-8126-347f9fa8438b").getMessage(), "Message");
        assertEquals(impl.getAnnouncements().get("863b7817-76d7-41b5-9186-0fd09d0aeec9").getMessage(), "Second Message");


        byte[] publicBytes = Base64.getDecoder().decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO+8oHVgN36CalszTX/XdEtQZK5jnaW6F7LEMSbLUbpVPx9p8blQzT4RzKveINE3i6UeA4eHMKEi41loimbo0AQWvdvLzO4rSM36ttehmzMRRGI/s883uobTZai7MtCagmOnZaWk2YtwP3/5ozV+IgFljgsTwah93WoJOp6j//1wIDAQAB");
        byte[] publicBytes2 = Base64.getDecoder().decode("MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDgUqYUhdfgAxafcqALwwRor9dy8/2HtTWFfY+51ywqZqpx4dljZkddKzVoZQh0Zgqx4oOU8NWNY5ibl1bGHYCfqF/6cSEo18+QaorBKZQeUG6b//Kqx0ESvfJJT9ny8MvKlnwTDhog/EfPGhX8O3MUCiWk+Nx/EqLcqR6YDkhqxwIDAQAB");

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);
        X509EncodedKeySpec keySpec2 = new X509EncodedKeySpec(publicBytes2);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        PublicKey pubKey2 = keyFactory.generatePublic(keySpec2);

        assertEquals(impl.getUsers().get(pubKey).getUsername(), "USER");
        assertEquals(impl.getUsers().get(pubKey2).getUsername(), "USER2");

    }

    @Test
    public void validRegister() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException, InvalidKeyException, SignatureException {

        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("valid_load_target_4.json").getPath();
        PersistenceManager manager = new PersistenceManager(path);

        KeyPairGenerator keygen = KeyPairGenerator.getInstance("RSA");
        keygen.initialize(1024);
        PublicKey pubKey = keygen.generateKeyPair().getPublic();
        String userName = "USERNAME";

        JsonArray jsonArray = manager.readSaveFile();

        JsonObject json = Json.createObjectBuilder()
                .add("Type", "Register")
                .add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
                .add("User", userName)
                .build();

        manager.save(json);

        jsonArray = manager.readSaveFile();

        for(int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            if( i == (jsonArray.size() - 1) && operation.getString("Type").equals("Register")){
                assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
                assertEquals(operation.getString("User"), userName);
            }
        }
    }

    @Test
    public void validPost() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException,
            CommonDomainException, InvalidKeyException, SignatureException {

        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("valid_load_target_2.json").getPath();
        PersistenceManager manager = new PersistenceManager(path);

        String userName = "USERNAME";
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


        JsonObject json = Json.createObjectBuilder()
                .add("Type", "Post")
                .add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
                .add("Signature", Base64.getEncoder().encodeToString(signature))
                .add("References", "null")
                .add("Identifier", identifier)
                .add("Message", message)
                .build();

        manager.save(json);


        JsonArray jsonArray = manager.readSaveFile();
        for(int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            if( i == (jsonArray.size() - 1) && operation.getString("Type").equals("Post")){
                assertEquals(operation.getString("Message"), message);
                assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
                assertEquals(operation.getString("Signature"), Base64.getEncoder().encodeToString(signature));
                assertEquals(operation.getString("References"), "null");
                assertEquals(operation.getString("Identifier"), identifier);
            }
        }

    }

    @Test
    public void validPostGeneral() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException,
            CommonDomainException, InvalidKeyException, SignatureException {


        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("valid_load_target_3.json").getPath();
        PersistenceManager manager = new PersistenceManager(path);

        String userName = "USERNAME";
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


        JsonObject json = Json.createObjectBuilder()
                .add("Type", "PostGeneral")
                .add("Public Key", Base64.getEncoder().encodeToString(pubKey.getEncoded()))
                .add("Signature", Base64.getEncoder().encodeToString(signature))
                .add("References", "null")
                .add("Identifier", identifier)
                .add("Message", message)
                .build();

        manager.save(json);

        JsonArray jsonArray = manager.readSaveFile();
        for(int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            if(i == (jsonArray.size() - 1) && operation.getString("Type").equals("PostGeneral")){
                assertEquals(operation.getString("Message"), message);
                assertEquals(operation.getString("Public Key"), Base64.getEncoder().encodeToString(pubKey.getEncoded()));
                assertEquals(operation.getString("Signature"), Base64.getEncoder().encodeToString(signature));
                assertEquals(operation.getString("References"), "null");
                assertEquals(operation.getString("Identifier"), identifier);
            }
        }

    }

    @Test(expected = JsonException.class)
    public void loadInvalidFile() throws IOException, SignatureException, CommonDomainException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("empty.json").getPath();

        PersistenceManager manager = new PersistenceManager(path);
        manager.load();
    }

    @Test
    public void loadNoOperationsFile() throws IOException, SignatureException, CommonDomainException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("no_operations.json").getPath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 0);
        assertEquals(impl._users.size(), 0);
    }

    @Test
    public void loadGeneralTest() throws IOException, SignatureException, CommonDomainException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("valid_load_target.json").getPath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 2);
        assertEquals(impl._users.size(), 2);
    }

    @Test
    public void loadGeneralTestWithSwap() throws IOException, SignatureException, CommonDomainException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException {
        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("valid_load_target_with_swap.json").getPath();

        PersistenceManager manager = new PersistenceManager(path);
        ServiceDPASPersistentImpl impl = manager.load();
        assertEquals(impl._announcements.size(), 2);
        assertEquals(impl._users.size(), 2);
    }

}
