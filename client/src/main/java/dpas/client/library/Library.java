package dpas.client.library;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import com.google.protobuf.ByteString;

import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.PostRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.StatusRuntimeException;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;

public class Library {

	public ServiceDPASGrpc.ServiceDPASBlockingStub _stub;

	public Library(String host, int port) {
		var _channel = NettyChannelBuilder.forAddress(host, port).usePlaintext().build();
		_stub = ServiceDPASGrpc.newBlockingStub(_channel);
	}

	public void register(PublicKey publicKey) {
		try {
			_stub.register(Contract.RegisterRequest.newBuilder()
					.setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
					.build());
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		}

	}

	public void post(PublicKey key, char[] message, Announcement[] a, String identifier, PrivateKey privateKey) {
		try {
			_stub.post(createPostRequest(key, message, a, identifier, privateKey));
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		} catch (CommonDomainException e) {
			System.out.println("Could not create signature from values provided");
		}
	}

	public void postGeneral(PublicKey key, char[] message, Announcement[] a, String identifier, PrivateKey privateKey) {
		try {
			_stub.postGeneral(createPostRequest(key, message, a, identifier, privateKey));
		} catch (StatusRuntimeException e) {
			System.out.println("An error ocurred: " + e.getMessage());
		} catch (CommonDomainException e) {
			System.out.println("Could not create signature from values provided");
		}
	}

	public Announcement[] read(PublicKey publicKey, String username, int number) {
		try {
			var reply = _stub.read(Contract.ReadRequest.newBuilder()
							.setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
							.setNumber(number)
							.build());
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


	private PostRequest createPostRequest(PublicKey key, char[] message, Announcement[] a, String identifier,
			PrivateKey privateKey) throws CommonDomainException {

		List<String> references = a == null ? new ArrayList<String>() 
					: Stream.of(a).map(Announcement::getIdentifier).collect(Collectors.toList());

		byte[] signature = dpas.common.domain.Announcement.generateSignature(privateKey, String.valueOf(message), identifier, references, key);
		
		return PostRequest.newBuilder()
				.setIdentifier(identifier)
				.setMessage(String.copyValueOf(message))
				.setPublicKey(ByteString.copyFrom(key.getEncoded()))
				.addAllReferences(references)
				.setSignature(ByteString.copyFrom(signature))
				.build();
	}

}
