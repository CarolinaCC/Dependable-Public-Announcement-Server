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

import static dpas.common.domain.utils.CryptographicConstants.ASYMMETRIC_KEY_ALGORITHM;
import static dpas.common.domain.utils.JsonConstants.*;


public class PersistenceManager {

    public static final String ROOT_KEY = "Operations";

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
        objectBuilder.add(ROOT_KEY, arrayBuilder.build());

        try (JsonWriter jsonWriter = Json.createWriter(new BufferedWriter(new FileWriter(_swapFile, false)))) {
            jsonWriter.writeObject(objectBuilder.build());
        }
        Files.move(Paths.get(_swapFile.getPath()), Paths.get(_path), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
    }

    @Deprecated
    public synchronized ServiceDPASPersistentImpl load() throws GeneralSecurityException, CommonDomainException, IOException {
        JsonArray jsonArray = readSaveFile();
        ServiceDPASPersistentImpl service = new ServiceDPASPersistentImpl(this);
        parseJsonArray(jsonArray, service);
        return service;
    }

    @Deprecated
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

            byte[] keyBytes = Base64.getDecoder().decode(operation.getString(PUBLIC_KEY));
            PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(keyBytes));

            if (operation.getString(OPERATION_TYPE_KEY).equals(REGISTER_OP_TYPE)) {
                service.addUser(key);
                userSeqs.put(key, 0L);
            } else {
                byte[] signature = Base64.getDecoder().decode(operation.getString(SIGNATURE_KEY));
                JsonArray jsonReferences = operation.getJsonArray(REFERENCES_KEY);

                // creating new array list of references
                ArrayList<String> references = new ArrayList<>();
                for (int j = 0; j < jsonReferences.size(); j++) {
                    references.add(jsonReferences.getString(j));
                }

                JsonObject jsonBroadCastProof = operation.getJsonObject(BROADCAST_PROOF_KEY);
                Map<String, String> broadcastproof = new HashMap<>();
                Set<String> keys = jsonBroadCastProof.keySet();
                for (String mapKey : keys) {
                    broadcastproof.put(mapKey, jsonBroadCastProof.getString(mapKey));
                }

                long seq = operation.getInt(SEQUENCER_KEY);

                if (operation.getString(OPERATION_TYPE_KEY).equals(POST_OP_TYPE))
                    service.addAnnouncement(operation.getString(MESSAGE_KEY), key, signature, references, seq, broadcastproof);
                else
                    service.addGeneralAnnouncement(operation.getString(MESSAGE_KEY), key, signature, references, seq, broadcastproof);
                userSeqs.put(key, userSeqs.get(key) + 1);
            }
        }
    }

    public JsonArray readSaveFile() throws FileNotFoundException {
        try (JsonReader reader = Json.createReader(new BufferedInputStream(new FileInputStream(_file)))) {
            return reader.readObject().getJsonArray(ROOT_KEY);
        }
    }

    public void clearSaveFile() throws IOException {
        FileUtils.write(_file, "{ \"" + ROOT_KEY +"\" : [] }", StandardCharsets.UTF_8, false);
    }
}
