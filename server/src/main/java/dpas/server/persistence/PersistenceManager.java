package dpas.server.persistence;

import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.server.service.ServiceDPASImpl;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;

public class PersistenceManager {

    private ConcurrentHashMap<String, Announcement> _announcements;
    private ConcurrentHashMap<PublicKey, User> _users;
    private GeneralBoard _generalBoard;
    private File _file;
    public PersistenceManager(String path) throws IOException {
        _announcements = new ConcurrentHashMap<>();
        _users = new ConcurrentHashMap<>();
        _generalBoard = new GeneralBoard();

        if (Files.isDirectory(Paths.get(path))) {
            //Do something like throwing an exception
        }

        _file = new File(path);
        if (!Files.exists(Paths.get(path))) {
            //File does not exist
            _file.createNewFile();
            FileUtils.writeStringToFile(_file, "\"operation\" : []", StandardCharsets.UTF_8);
        }
    }

    public void save(String operation) {

    }

    public ServiceDPASImpl load() {
        return null;
    }
}
