package dpas.server.persistence;

import dpas.common.domain.exception.*;
import dpas.server.service.ServiceDPASPersistentImpl;
import org.apache.commons.io.FileUtils;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;


public class PersistenceManager {
    private File _file;

    public PersistenceManager(String path) throws IOException {


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
        BufferedWriter writer = new BufferedWriter(new FileWriter(json_swap));
        writer.write(operation);
        writer.close();

        Files.move(Paths.get(json_swap.getPath()), Paths.get(_file.getPath()), StandardCopyOption.ATOMIC_MOVE);
    }

    public ServiceDPASPersistentImpl load() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NullUserException, NullPublicKeyException, NullUsernameException, InvalidMessageSizeException, InvalidReferenceException, NullAnnouncementException, InvalidKeyException, SignatureException, InvalidSignatureException, NullSignatureException, InvalidUserException, NullMessageException {
        InputStream fis = new FileInputStream(_file);
        JsonReader reader = Json.createReader(fis);
        JsonArray jsonArray = reader.readObject().getJsonArray("operation");

        ServiceDPASPersistentImpl service = new ServiceDPASPersistentImpl(this);

        for (int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(operation.getString("Public Key"))));

            if (operation.getString("Type").equals("Register")) {
                service.addUser(operation.getString("User"), key);
            } else {
                byte[] signature = Base64.getDecoder().decode(operation.getString("Signature"));
                JsonArray refsJson = operation.getJsonArray("References");

                // creating new array list of references
                ArrayList<String> refs = new ArrayList<String>();
                for (int j = 0; j < refsJson.size(); j++) {
                    refs.add(refsJson.getString(j));
                }

                if (operation.getString("Type").equals("Post"))
                    service.addAnnouncement(operation.getString("Message"), key, signature, refs);
                else
                    service.addGeneralAnnouncement(operation.getString("Message"), key, signature, refs);
            }
        }
        return service;
    }
}
