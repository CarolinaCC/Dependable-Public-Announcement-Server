package dpas.server.persistence;

import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.server.service.ServiceDPASImpl;
import org.apache.commons.io.FileUtils;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;
import java.util.concurrent.ConcurrentHashMap;
import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.json.stream.JsonParser;


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

    public void save() {

    }

    public ServiceDPASImpl load() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NullUserException, NullPublicKeyException, NullUsernameException {
        InputStream fis = new FileInputStream(_file);
        JsonReader reader = Json.createReader(fis);
        JsonArray jsonArray = reader.readObject().getJsonArray("operation");

        if (jsonArray.isEmpty())
            return new ServiceDPASImpl();

        ServiceDPASImpl service = new ServiceDPASImpl();

        for (int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            if (operation.getString("Type").equals("Register")) {
                PublicKey key = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(operation.getString("Public Key"))));
                service.addUser(operation.getString("User"), key);
            }
            else if (operation.getString("Type").equals("Register")) {
                PublicKey key = KeyFactory.getInstance("RSA")
                        .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(operation.getString("Public Key"))));
                service.addUser(operation.getString("User"), key);
            }



        }

        return null;

    }
}
