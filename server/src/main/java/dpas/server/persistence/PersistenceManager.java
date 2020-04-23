package dpas.server.persistence;

import dpas.common.domain.exception.CommonDomainException;
import dpas.server.security.SecurityManager;
import dpas.server.service.ServiceDPASPersistentImpl;
import dpas.server.service.ServiceDPASReliableImpl;
import dpas.server.service.ServiceDPASSafeImpl;
import dpas.utils.link.PerfectStub;
import org.apache.commons.io.FileUtils;

import javax.json.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;


public class PersistenceManager {
    private final String _path;
    private final File _swapFile;
    private final File _file;


    public PersistenceManager(String path) throws IOException {
        if (path == null) {
            throw new RuntimeException();
        }
        if (Files.isDirectory(Paths.get(path))) {
            throw new RuntimeException();
        }

        _file = new File(path);
        if (!_file.exists()) {
            //File does not exist, start a new save file
            _file.createNewFile();
            clearSaveFile();
        }
        _path = path;
        _swapFile = new File(_file.getPath() + ".swap");
        _swapFile.createNewFile();
    }

    public synchronized void save(JsonValue operation) throws IOException {
        JsonArray jsonArray = readSaveFile();

        final JsonArrayBuilder arrayBuilder = Json.createArrayBuilder();
        jsonArray.forEach(arrayBuilder::add);
        arrayBuilder.add(operation);

        final JsonObjectBuilder objectBuilder = Json.createObjectBuilder();
        objectBuilder.add("Operations", arrayBuilder.build());

        try (JsonWriter jsonWriter = Json.createWriter(new BufferedWriter(new FileWriter(_swapFile, false)))) {
            jsonWriter.writeObject(objectBuilder.build());
        }
        Files.move(Paths.get(_swapFile.getPath()), Paths.get(_path), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    public synchronized ServiceDPASPersistentImpl load() throws GeneralSecurityException, CommonDomainException, IOException {
        JsonArray jsonArray = readSaveFile();
        ServiceDPASPersistentImpl service = new ServiceDPASPersistentImpl(this);
        parseJsonArray(jsonArray, service);
        return service;
    }

    public synchronized ServiceDPASSafeImpl load(SecurityManager manager, PrivateKey privateKey) throws GeneralSecurityException, CommonDomainException, IOException {
        JsonArray jsonArray = readSaveFile();
        ServiceDPASSafeImpl service = new ServiceDPASSafeImpl(this, privateKey, manager);
        parseJsonArray(jsonArray, service);
        return service;
    }

    public synchronized ServiceDPASReliableImpl load(SecurityManager manager, PrivateKey privateKey, List<PerfectStub> stubs, String serverId, int numFaults) throws GeneralSecurityException, CommonDomainException, IOException {
        JsonArray jsonArray = readSaveFile();
        var service = new ServiceDPASReliableImpl(this, privateKey, manager, stubs, serverId, numFaults);
        parseJsonArray(jsonArray, service);
        return service;
    }

    private void parseJsonArray(JsonArray jsonArray, ServiceDPASPersistentImpl service) throws GeneralSecurityException, CommonDomainException {
        Map<PublicKey, Long> userSeqs = new HashMap<>();
        for (int i = 0; i < jsonArray.size(); i++) {
            JsonObject operation = jsonArray.getJsonObject(i);

            byte[] keyBytes = Base64.getDecoder().decode(operation.getString("Public Key"));
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(keyBytes));

            if (operation.getString("Type").equals("Register")) {
                service.addUser(key);
                userSeqs.put(key, 0L);
            } else {
                byte[] signature = Base64.getDecoder().decode(operation.getString("Signature"));
                JsonArray jsonReferences = operation.getJsonArray("References");

                // creating new array list of references
                ArrayList<String> references = new ArrayList<>();
                for (int j = 0; j < jsonReferences.size(); j++) {
                    references.add(jsonReferences.getString(j));
                }

                JsonObject jsonBroadCastProof = operation.getJsonObject("BroadCastProof");
                Map<String, String> broadcastproof = new HashMap<>();
                Set<String> keys = jsonBroadCastProof.keySet();
                for (String mapKey : keys) {
                    broadcastproof.put(mapKey, jsonBroadCastProof.getString(mapKey));
                }

                long seq = operation.getInt("Sequencer");

                if (operation.getString("Type").equals("Post"))
                    service.addAnnouncement(operation.getString("Message"), key, signature, references, seq, broadcastproof);
                else
                    service.addGeneralAnnouncement(operation.getString("Message"), key, signature, references, seq, broadcastproof);
                userSeqs.put(key, userSeqs.get(key) + 1);
            }
        }
    }

    public JsonArray readSaveFile() throws FileNotFoundException {
        try (JsonReader reader = Json.createReader(new BufferedInputStream(new FileInputStream(_file)))) {
            return reader.readObject().getJsonArray("Operations");
        }
    }

    public void clearSaveFile() throws IOException {
        FileUtils.write(_file, "{ \"Operations\" : [] }", StandardCharsets.UTF_8, false);
    }
}
