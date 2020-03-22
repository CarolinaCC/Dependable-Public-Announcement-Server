package dpas.client.library;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

public class Library {

	public ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

	public Library(String host, int port) {
		var _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);
	}

	public void register(PublicKey publicKey, String username) {
		try {
			_stub.register(Contract.RegisterRequest.newBuilder()
					.setPublicKey(ByteString.copyFrom(publicKey.getEncoded())).setUsername(username).build());
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		}

	}

	public void post(PublicKey key, char[] message, String username, Announcement[] a, PrivateKey privateKey) {
		try {
			_stub.post(createPostRequest(key, message, username, a, privateKey));
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			System.out.println("Could not create signature from values provided");
		}
	}

	public void post(PublicKey key, char[] message, String username, Announcement[] a, byte[] signature) {
		try {
			_stub.post(createPostRequest(key, message, username, a, signature));
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		}
	}

	public void postGeneral(PublicKey key, char[] message, String username, Announcement[] a, PrivateKey privateKey) {
		try {
			_stub.postGeneral(createPostRequest(key, message, username, a, privateKey));
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		} catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
			System.out.println("Could not create signature from values provided");
		}
	}

	public void postGeneral(PublicKey key, char[] message, String username, Announcement[] a, byte[] signature) {
		try {
			_stub.postGeneral(createPostRequest(key, message, username, a, signature));
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		}
	}

	public Announcement[] read(PublicKey publicKey, String username, int number) {
		try {
			Contract.ReadReply reply = _stub
					.read(Contract.ReadRequest.newBuilder().setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
							.setUsername(username).setNumber(number).build());
			return (Announcement[]) reply.getAnnouncementsList().toArray();
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
			return null;
		}
	}

	public Announcement[] readGeneral(int number) {
		try {
			Contract.ReadReply reply = _stub.readGeneral(Contract.ReadRequest.newBuilder().setNumber(number).build());
			return (Announcement[]) reply.getAnnouncementsList().toArray();
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
			return null;
		}
	}

	private Contract.PostRequest createPostRequest(PublicKey key, char[] message, String username, Announcement[] a,
			byte[] signature) {
		List<String> identifiers = new ArrayList<String>();
		for (Announcement announcement : a) {
			identifiers.add(announcement.getIdentifier());
		}

		Contract.PostRequest postRequest = Contract.PostRequest.newBuilder()
				.setPublicKey(ByteString.copyFrom(key.getEncoded())).setMessage(String.valueOf(message))
				.setSignature(ByteString.copyFrom(signature)).setUsername(username).addAllReferences(identifiers)
				.build();
		return postRequest;
	}

	private Contract.PostRequest createPostRequest(PublicKey key, char[] message, String username, Announcement[] a,
			PrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {

		Signature signature = Signature.getInstance("SHA256withRSA");
		signature.initSign(privateKey);
		signature.update(String.valueOf(message).getBytes());

		return createPostRequest(key, message, username, a, signature.sign());
	}

}
