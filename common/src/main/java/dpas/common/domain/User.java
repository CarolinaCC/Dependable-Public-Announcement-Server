package dpas.common.domain;

import dpas.common.domain.constants.JsonConstants;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;

import static dpas.common.domain.constants.JsonConstants.OPERATION_TYPE_KEY;
import static dpas.common.domain.constants.JsonConstants.PUBLIC_KEY;

public class User {

    private final PublicKey publicKey;
    private final UserBoard userBoard;


    public User(PublicKey publicKey) throws NullPublicKeyException, NullUserException {
        checkArguments(publicKey);
        this.publicKey = publicKey;
        this.userBoard = new UserBoard(this);
    }

    public void checkArguments(PublicKey publicKey) throws NullPublicKeyException {
        if (publicKey == null) {
            throw new NullPublicKeyException("Invalid Public Key: Cannot be null");
        }
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public UserBoard getUserBoard() {
        return this.userBoard;
    }

    public JsonObject toJson() {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        String pubKey = Base64.getEncoder().encodeToString(this.publicKey.getEncoded());

        jsonBuilder.add(OPERATION_TYPE_KEY, JsonConstants.REGISTER_OP_TYPE);
        jsonBuilder.add(PUBLIC_KEY, pubKey);

        return jsonBuilder.build();
    }

    @Override
    public boolean equals(Object obj) {
        if (obj instanceof User) {
            User other = (User) obj;
            return Arrays.equals(publicKey.getEncoded(), other.getPublicKey().getEncoded());
        }
        return false;
    }
}
