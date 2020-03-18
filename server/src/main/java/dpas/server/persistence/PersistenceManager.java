package dpas.server.persistence;

import dpas.common.domain.exception.*;
import dpas.server.service.ServiceDPASPersistentImpl;
import org.apache.commons.io.FileUtils;

import javax.json.*;
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
import java.util.List;


public class PersistenceManager {
    private String _path;
    private File _swapFile;
    private FileInputStream _fileStream;


    public PersistenceManager(String path) throws IOException {
        if (Files.isDirectory(Paths.get(path))) {
            throw new RuntimeException();
        }

        File file = new File(path);
        if (!Files.exists(Paths.get(path))) {
            //File does not exist, start a new save file
            file.createNewFile();
            FileUtils.writeStringToFile(file, "\"operation\" : []", StandardCharsets.UTF_8);
        }
        _path = path;
        _swapFile = new File(file.getPath() + ".swap");
        _fileStream = new FileInputStream(file);
    }

    public synchronized void save(JsonValue operation) throws IOException {
        JsonArray jsonArray = readSaveFile();

        final JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        for (int i = 0; i < jsonArray.size(); ++i) {
            arrayBuilder.add(jsonArray.getJsonObject(i));
        }
        arrayBuilder.add(operation);

        final JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
        objectBuilder.add("Operations", arrayBuilder.build());
        try (JsonWriter jsonWriter = Json.createWriter(new FileWriter(_swapFile, false))) {
            jsonWriter.writeObject(objectBuilder.build());
        }

        Files.move(Paths.get(_swapFile.getPath()), Paths.get(_path), StandardCopyOption.ATOMIC_MOVE);

    }

    public ServiceDPASPersistentImpl load() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NullUserException, NullPublicKeyException, NullUsernameException, InvalidMessageSizeException, InvalidReferenceException, NullAnnouncementException, InvalidKeyException, SignatureException, InvalidSignatureException, NullSignatureException, InvalidUserException, NullMessageException {

        JsonArray jsonArray = readSaveFile();

        ServiceDPASPersistentImpl service = new ServiceDPASPersistentImpl(this);

        for (int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);

            byte[] keyBytes = Base64.getDecoder().decode(operation.getString("Public Key"));
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

            if (operation.getString("Type").equals("Register")) {
                service.addUser(operation.getString("User"), key);
            } else {
                byte[] signature = Base64.getDecoder().decode(operation.getString("Signature"));
                JsonArray jsonReferences = operation.getJsonArray("References");

                // creating new array list of references
                ArrayList<String> references = new ArrayList<String>();
                for (int j = 0; j < jsonReferences.size(); j++) {
                    references.add(jsonReferences.getString(j));
                }

                String identifier = operation.getString("Identifier");

                if (operation.getString("Type").equals("Post"))
                    service.addAnnouncement(operation.getString("Message"), key, signature, references, identifier);
                else
                    service.addGeneralAnnouncement(operation.getString("Message"), key, signature, references, identifier);
            }

        }
        return service;
    }

    private JsonArray readSaveFile() throws IOException {
        _fileStream.reset();
        try (JsonReader reader = Json.createReader(_fileStream)) {
            return reader.readObject().getJsonArray("Operations");
        }
    }

    public JsonValue registerToJson(PublicKey key, String user) {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        String pubKey = Base64.getEncoder().encodeToString(key.getEncoded());

        jsonBuilder.add("Type", "Register");
        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("User", user);

        return jsonBuilder.build();
    }


    public JsonValue postToJson(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        String pubKey = Base64.getEncoder().encodeToString(key.getEncoded());
        String sign = Base64.getEncoder().encodeToString(signature);
        final JsonArrayBuilder builder = Json.createArrayBuilder();

        for (String reference : references) {
            builder.add(reference);
        }

        jsonBuilder.add("Type", "Post");
        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("User", user);
        jsonBuilder.add("Message", message);
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Identifier", identifier);
        jsonBuilder.add("References", builder.build());

        return jsonBuilder.build();
    }

    public JsonValue postGeneralToJson(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        String pubKey = Base64.getEncoder().encodeToString(key.getEncoded());
        String sign = Base64.getEncoder().encodeToString(signature);
        final JsonArrayBuilder builder = Json.createArrayBuilder();

        for (String reference : references) {
            builder.add(reference);
        }

        jsonBuilder.add("Type", "PostGeneral");
        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("User", user);
        jsonBuilder.add("Message", message);
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Identifier", identifier);
        jsonBuilder.add("References", builder.build());

        return jsonBuilder.build();
    }


}
