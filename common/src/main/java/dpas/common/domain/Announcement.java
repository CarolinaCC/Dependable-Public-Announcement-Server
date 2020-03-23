package dpas.common.domain;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.json.Json;
import javax.json.JsonArrayBuilder;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;

import com.google.protobuf.ByteString;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidMessageSizeException;
import dpas.common.domain.exception.InvalidSignatureException;
import dpas.common.domain.exception.NullAnnouncementException;
import dpas.common.domain.exception.NullMessageException;
import dpas.common.domain.exception.NullSignatureException;
import dpas.common.domain.exception.NullUserException;
import dpas.grpc.contract.Contract;

public class Announcement {
	private byte[] _signature;
	private User _user;
	private String _message;
	private ArrayList<Announcement> _references; // Can be null
	private String _identifier;
	private AnnouncementBoard _board;

	public Announcement(byte[] signature, User user, String message, ArrayList<Announcement> references,
			String identifier, AnnouncementBoard board) throws CommonDomainException, InvalidSignatureException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		checkArguments(signature, user, message, references);
		checkSignature(signature, user, message, identifier , getReferenceStrings(references), board.getPublicKey());
		this._message = message;
		this._signature = signature;
		this._user = user;
		this._references = references;
		this._identifier = identifier;
		this._board = board;

	}

	public void checkArguments(byte[] signature, User user, String message, ArrayList<Announcement> references)
			throws NullSignatureException, NullMessageException, NullAnnouncementException, NullUserException,
			InvalidMessageSizeException {

		if (signature == null) {
			throw new NullSignatureException("Invalid Signature provided: null");
		}
		if (user == null) {
			throw new NullUserException("Invalid User provided: null");
		}
		if (message == null) {
			throw new NullMessageException("Invalid Message Provided: null");
		}

		if (message.length() > 255) {
			throw new InvalidMessageSizeException("Invalid Message Length provided: over 255 characters");
		}

		if (references != null) {
			if (references.contains(null)) {
				throw new NullAnnouncementException("Invalid Reference: A reference cannot be null");
			}
		}
	}

	public void checkSignature(byte[] signature, User user, String message, String identifier, List<String> references, PublicKey boardKey)
			throws InvalidSignatureException, InvalidKeyException, NoSuchAlgorithmException, SignatureException {

		var builder = new StringBuilder();
		builder.append(message);
		builder.append(identifier);
		references.forEach(ref -> builder.append(ref));
		
		builder.append(Base64.getEncoder().encodeToString(boardKey.getEncoded()));
		
		
		byte[] messageBytes = builder.toString().getBytes();
		PublicKey publicKey = user.getPublicKey();

		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify(publicKey);
		sign.update(messageBytes);

		try {
			if (!sign.verify(signature))
				throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");
		} catch (SignatureException e) {
			throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");
		}
	}

	public String getMessage() {
		return this._message;
	}

	public byte[] getSignature() {
		return this._signature;
	}

	public ArrayList<Announcement> getReferences() {
		return this._references;
	}

	public User getUser() {
		return this._user;
	}


	public String getIdentifier() {
		return _identifier;
	}

	public Contract.Announcement toContract() {

		Stream<Announcement> myStream = _references.stream();
		List<String> announcementToIdentifier = myStream.map(Announcement::getIdentifier).collect(Collectors.toList());

		return Contract.Announcement.newBuilder()
				.setMessage(_message)
				.addAllReferences(announcementToIdentifier)
				.setIdentifier(_identifier)
				.setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
				.setSignature(ByteString.copyFrom(_signature))
				.build();
	}

	public JsonObject toJson(String type) {
		JsonObjectBuilder jsonBuilder = Json.createObjectBuilder();
		String pubKey = Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded());
		String sign = Base64.getEncoder().encodeToString(_signature);
		final JsonArrayBuilder builder = Json.createArrayBuilder();

		for (Announcement reference : _references) {
			builder.add(reference.getIdentifier());
		}

		jsonBuilder.add("Type", type);
		jsonBuilder.add("Public Key", pubKey);
		jsonBuilder.add("Message", _message);
		jsonBuilder.add("Signature", sign);
		jsonBuilder.add("Identifier", _identifier);
		jsonBuilder.add("References", builder.build());

		return jsonBuilder.build();
	}
	
	public static List<String> getReferenceStrings(List<Announcement> references) {
		return references == null ? new ArrayList<String>() 
				: references.stream().map(Announcement::getIdentifier).collect(Collectors.toList());
	}
	
	public static byte[] generateSignature(PrivateKey privKey, String message, String identifier, List<String> references, PublicKey boardKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		var builder = new StringBuilder();
		builder.append(message);
		builder.append(identifier);
		
		if (references != null) {
			references.forEach(ref -> builder.append(ref));
		}
		
		builder.append(Base64.getEncoder().encodeToString(boardKey.getEncoded()));
		
		byte[] messageBytes = builder.toString().getBytes();
		
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initSign(privKey);
		sign.update(messageBytes);
		return sign.sign();
	}
}
