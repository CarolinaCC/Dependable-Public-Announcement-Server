package dpas.server.service;

import dpas.common.domain.exception.*;
import dpas.server.persistence.PersistenceManager;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import javax.json.JsonException;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

import static org.junit.Assert.assertEquals;

public class PersistenceManagerTest {

    @Before
    public void setup() {

    }

    @After
    public void teardown() {

    }

    @Test(expected = JsonException.class)
    public void loadInvalidFile() throws IOException, SignatureException, NullUserException, NullAnnouncementException, InvalidUserException, InvalidKeySpecException, NullMessageException, NoSuchAlgorithmException, InvalidMessageSizeException, NullPublicKeyException, InvalidKeyException, NullUsernameException, InvalidSignatureException, NullSignatureException, InvalidReferenceException {
        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("empty.json").getPath();;
        PersistenceManager manager = new PersistenceManager(path);
        manager.load();
    }

    @Test
    public void loadNoOperationsFile() throws IOException, SignatureException, NullUserException, NullAnnouncementException, InvalidUserException, InvalidKeySpecException, NullMessageException, NoSuchAlgorithmException, InvalidMessageSizeException, NullPublicKeyException, InvalidKeyException, NullUsernameException, InvalidSignatureException, NullSignatureException, InvalidReferenceException {
        ClassLoader classLoader = getClass().getClassLoader();
        String path = classLoader.getResource("no_operations.json").getPath();;
        PersistenceManager manager = new PersistenceManager(path);
        manager.load();
    }

}
