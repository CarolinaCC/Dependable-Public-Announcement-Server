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
    private File _file;

    public PersistenceManager(String path) throws IOException {


        if (Files.isDirectory(Paths.get(path))) {
            throw new RuntimeException();
        }

        _file = new File(path);
        if (!Files.exists(Paths.get(path))) {
            //File does not exist
            _file.createNewFile();
            FileUtils.writeStringToFile(_file, "\"operation\" : []", StandardCharsets.UTF_8);
        }
    }

    public void save(JsonValue operation) throws IOException {

        File json_swap = new File(_file.getPath() + ".swap");


        try (JsonReader reader = Json.createReader(new FileInputStream(_file))) {
            try (JsonWriter jsonWriter = Json.createWriter(new FileWriter(json_swap, false))) {

                final JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
                JsonArray jsonArray = reader.readObject().getJsonArray("Operations");
                for (int i = 0; i < jsonArray.size(); ++i) {
                    arrayBuilder.add(jsonArray.getJsonObject(i));
                }
                arrayBuilder.add(operation);


                final JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
                objectBuilder.add("Operations", arrayBuilder.build());
                jsonWriter.writeObject(objectBuilder.build());
            }
        }

        Files.move(Paths.get(json_swap.getPath()), Paths.get(_file.getPath()), StandardCopyOption.ATOMIC_MOVE);

    }

    public ServiceDPASPersistentImpl load() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NullUserException, NullPublicKeyException, NullUsernameException, InvalidMessageSizeException, InvalidReferenceException, NullAnnouncementException, InvalidKeyException, SignatureException, InvalidSignatureException, NullSignatureException, InvalidUserException, NullMessageException {
        InputStream fis = new FileInputStream(_file);
        JsonReader reader = Json.createReader(fis);
        JsonArray jsonArray = reader.readObject().getJsonArray("Operations");

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

    public JsonValue registerToJSON(PublicKey key, String user) {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        String pubKey = Base64.getEncoder().encodeToString(key.getEncoded());

        jsonBuilder.add("Type", "Register");
        jsonBuilder.add("Public Key", pubKey);
        jsonBuilder.add("User", user);

        return jsonBuilder.build();
    }


    public JsonValue postToJSon(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {

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
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Identifier", identifier);
        jsonBuilder.add("References", builder.build());

        return jsonBuilder.build();
    }

    public JsonValue postGeneralToJSon(PublicKey key, String user, byte[] signature, String message, String identifier, List<String> references) {

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
        jsonBuilder.add("Signature", sign);
        jsonBuilder.add("Identifier", identifier);
        jsonBuilder.add("References", builder.build());

        return jsonBuilder.build();
    }


}
