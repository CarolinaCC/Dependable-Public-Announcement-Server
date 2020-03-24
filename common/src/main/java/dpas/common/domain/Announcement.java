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
import java.util.stream.Collectors;

import javax.json.Json;
import javax.json.JsonObject;

import com.google.protobuf.ByteString;

import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidBoardException;
import dpas.common.domain.exception.InvalidMessageSizeException;
import dpas.common.domain.exception.InvalidReferenceException;
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
	private List<Announcement> _references; // Can be null
	private String _identifier;
	private AnnouncementBoard _board;

	public Announcement(byte[] signature, User user, String message, List<Announcement> references,
			String identifier, AnnouncementBoard board) throws CommonDomainException{

		checkArguments(signature, user, message, identifier, references, board);
		checkSignature(signature, user, message, identifier , getReferenceStrings(references), board.getPublicKey());
		_message = message;
		_signature = signature;
		_user = user;
		_references = references;
		_identifier = identifier;
		_board = board;
	}
	
	public Announcement(PrivateKey signatureKey, User user, String message, List<Announcement> references,
			String identifier, AnnouncementBoard board) throws CommonDomainException {
		
		this(generateSignature(signatureKey, message, identifier, getReferenceStrings(references), board),
			user, message, references, identifier, board);
	}
	

	public void checkArguments(byte[] signature, User user, String message, String identifier, 
			List<Announcement> references, AnnouncementBoard board) throws CommonDomainException  {

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
		
		if (identifier == null) {
			throw new InvalidReferenceException("Invalid Announcement: Reference can't be null");
		}
		
		if (board == null) {
			throw new InvalidBoardException("Invalid Board Provided: can't be null");
		}

		if (references != null) {
			if (references.contains(null)) {
				throw new NullAnnouncementException("Invalid Reference: A reference cannot be null");
			}
		}
	}
	
	public void checkSignature(byte[] signature, User user, String message, String identifier, 
			List<String> references, PublicKey boardKey) throws CommonDomainException{
		try {
			
			byte[] messageBytes = generateMessageBytes(message, identifier, references, boardKey);
			PublicKey publicKey = user.getPublicKey();

			Signature sign = Signature.getInstance("SHA256withRSA");
			sign.initVerify(publicKey);
			sign.update(messageBytes);

			if (!sign.verify(signature))
				throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");
		
		}catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e ) {
			throw new InvalidSignatureException("Invalid Signature: Signature Could not be verified");
		}
	}


	public String getMessage() {
		return _message;
	}

	public byte[] getSignature() {
		return _signature;
	}

	public List<Announcement> getReferences() {
		return _references;
	}

	public User getUser() {
		return _user;
	}


	public String getIdentifier() {
		return _identifier;
	}
	
	public Contract.Announcement toContract() {

		var references = getReferenceStrings(_references);
		
		var announcement = Contract.Announcement.newBuilder()
		.setMessage(_message)
		.addAllReferences(references)
		.setIdentifier(_identifier)
		.setPublicKey(ByteString.copyFrom(_user.getPublicKey().getEncoded()))
		.setSignature(ByteString.copyFrom(_signature))
		.build();
		
		return announcement;
	}

	public JsonObject toJson(String type) {
		var jsonBuilder = Json.createObjectBuilder();
		
		String pubKey = Base64.getEncoder().encodeToString(_user.getPublicKey().getEncoded());
		String sign = Base64.getEncoder().encodeToString(_signature);
		
		final var arrayBuilder = Json.createArrayBuilder();		
		getReferenceStrings(_references).forEach(ref -> arrayBuilder.add(ref));

		jsonBuilder.add("Type", type);
		jsonBuilder.add("Public Key", pubKey);
		jsonBuilder.add("Message", _message);
		jsonBuilder.add("Signature", sign);
		jsonBuilder.add("Identifier", _identifier);
		jsonBuilder.add("References", arrayBuilder.build());

		return jsonBuilder.build();
	}
		
	public static byte[] generateSignature(PrivateKey privKey, String message, String identifier, 
			List<String> references, PublicKey boardKey) throws CommonDomainException {
		try {
			var messageBytes = generateMessageBytes(message, identifier, references, boardKey);
			var sign = Signature.getInstance("SHA256withRSA");
			sign.initSign(privKey);
			sign.update(messageBytes);
			return sign.sign();
		} catch(NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new InvalidSignatureException("Invalid Signature: could not be created");
		}
	}
	

	public static byte[] generateSignature(PrivateKey privKey, String message, String identifier, 
			List<String> references, AnnouncementBoard board) throws CommonDomainException {
		
		return generateSignature(privKey, message, identifier, references, board.getPublicKey());
	}
	
	public static List<String> getReferenceStrings(List<Announcement> references) {
		return references == null ? new ArrayList<String>() 
				: references.stream().map(Announcement::getIdentifier).collect(Collectors.toList());
	}
	
	private static byte[] generateMessageBytes(String message, String identifier, List<String> references, PublicKey boardKey) {
		var builder = new StringBuilder();
		builder.append(message);
		builder.append(identifier);
		if (references != null) {
			references.forEach(ref -> builder.append(ref));
		}
		builder.append(Base64.getEncoder().encodeToString(boardKey.getEncoded()));
		return builder.toString().getBytes();
	}
	
	
	
}
