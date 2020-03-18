package dpas.server.service;

import dpas.server.persistence.PersistenceManager;
import org.apache.commons.io.FileUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;

public class PersistenceManagerTest {

    @Before
    public void setup() {

    }

    @After
    public void teardown() {

    }

    @Test(expected = RuntimeException.class)
    public void constructorFileIsDirectory() throws IOException {
        new PersistenceManager("/tmp");
    }

    @Test
    public void constructorFileDoesNotExist() throws IOException {
        new PersistenceManager("/tmp/testFile_1");
        String content = FileUtils.readFileToString(new File("/tmp/testFile_1"), StandardCharsets.UTF_8);
        assertEquals(content, "\"operation\" : []");
    }
}
