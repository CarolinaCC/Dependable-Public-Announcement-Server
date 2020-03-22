package dpas.common.domain;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.grpc.contract.Contract;

public class User {

	private String _username;
	private PublicKey _publicKey;
	private UserBoard _userBoard;

	public User(String username, PublicKey publicKey)
			throws NullPublicKeyException, NullUsernameException, NullUserException {
		checkArguments(username, publicKey);
		this._username = username;
		this._publicKey = publicKey;
		this._userBoard = new UserBoard(this);
	}

	public void checkArguments(String username, PublicKey publicKey)
			throws NullPublicKeyException, NullUsernameException {
		if (username == null || username.isBlank()) {
			throw new NullUsernameException("Invalid Username: Cannot be null or blank");
		}

		if (publicKey == null) {
			throw new NullPublicKeyException("Invalid Public Key: Cannot be null");
		}
	}

	public String getUsername() {
		return _username;
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
		jsonBuilder.add("User", _username);

		return jsonBuilder.build();
	}

	public static User fromRequest(Contract.RegisterRequest request)
			throws NoSuchAlgorithmException, InvalidKeySpecException, CommonDomainException {
		PublicKey key = KeyFactory.getInstance("RSA")
				.generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
		String username = request.getUsername();
		return new User(username, key);
	}
}
