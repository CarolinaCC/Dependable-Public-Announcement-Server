package dpas.common.domain;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.grpc.contract.Contract;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.concurrent.atomic.AtomicLong;

public class User {

    private PublicKey _publicKey;
    private UserBoard _userBoard;
    private AtomicLong _seq;

    public User(PublicKey publicKey) throws NullPublicKeyException, NullUserException {
        checkArguments(publicKey);
        this._publicKey = publicKey;
        this._userBoard = new UserBoard(this);
        this._seq = new AtomicLong(0);
    }

    public void checkArguments(PublicKey publicKey) throws NullPublicKeyException {
        if (publicKey == null) {
            throw new NullPublicKeyException("Invalid Public Key: Cannot be null");
        }
    }

    public PublicKey getPublicKey() {
        return _publicKey;
    }

    public UserBoard getUserBoard() {
        return _userBoard;
    }

    public JsonObject toJson() {

        JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
        String pubKey = Base64.getEncoder().encodeToString(_publicKey.getEncoded());

        jsonBuilder.add("Type", "Register");
        jsonBuilder.add("Public Key", pubKey);

        return jsonBuilder.build();
    }

    public static User fromRequest(Contract.RegisterRequest request)
            throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        return new User(key);
    }

    public long getSeq() {
        return _seq.get();
    }

    public void incrSeq(long seq) {
        this._seq.getAndAdd(seq);
    }
}
