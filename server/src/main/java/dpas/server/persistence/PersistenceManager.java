package dpas.server.persistence;

import com.google.gson.Gson;
import com.google.gson.JsonElement;
import com.google.gson.JsonPrimitive;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.server.service.ServiceDPASImpl;
import org.apache.commons.io.FileUtils;
import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import javax.json.*;
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

    public void save(String operation) throws IOException {

        File json_swap = new File(_file.getPath() + ".swap");
        FileUtils.copyFile(_file, json_swap);

        /*BufferedWriter writer = new BufferedWriter(new FileWriter(json_swap));
        writer.write(operation);
        writer.close();*/

        InputStream fis = new FileInputStream(json_swap);
        JsonReader reader = Json.createReader(fis);
        JsonArray jsonArray = reader.readObject().asJsonArray();

        for(int i = 0; i < jsonArray.size(); i++) {
            if (i == jsonArray.size() - 1) jsonArray.set(i, operation);
        }

        Files.move(Paths.get(json_swap.getPath()), Paths.get(_file.getPath()), StandardCopyOption.ATOMIC_MOVE);

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

    public JsonValue PostStringTOJSon(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();

        String pubKey = Base64.getEncoder().encodeToString(key.getEncoded());
        String sign = Base64.getEncoder().encodeToString(signature);
        new Json.createArrayBuilder();

        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("User", user);
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Identifier", identifier);
        jsonBuilder.add("References", att);

    }


}
