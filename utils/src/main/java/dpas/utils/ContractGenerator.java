package dpas.utils;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract.*;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContractGenerator {

    public static ServerHello generateServerHello(PrivateKey privateKey, long seq, String sessionNonce) throws IOException, GeneralSecurityException {
        return ServerHello.newBuilder()
                .setSeq(seq)
                .setSessionNonce(sessionNonce)
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(sessionNonce, seq, privateKey)))
                .build();
    }

    public static ClientHello generateClientHello(PrivateKey privateKey, PublicKey publicKey, String sessionNonce) throws IOException, GeneralSecurityException {
        return ClientHello.newBuilder()
                .setSessionNonce(sessionNonce)
                .setPublicKey(ByteString.copyFrom(publicKey.getEncoded()))
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(sessionNonce, publicKey, privateKey)))
                .build();
    }

    public static SafePostRequest generatePostRequest(PublicKey serverKey, PublicKey pubKey, PrivateKey privKey,
                                                      String message, String nonce, long seq,
                                                      String boardIdentifier, Announcement[] a)
            throws GeneralSecurityException, IOException, CommonDomainException {
        byte[] encodedMessage = CypherUtils.cipher(message.getBytes(), serverKey);

        List<String> references = a == null ? new ArrayList<>()
                : Stream.of(a).map(Announcement::getHash).collect(Collectors.toList());

        byte[] signature = dpas.common.domain.Announcement.generateSignature(privKey, message, references, boardIdentifier);

        var request = SafePostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMessage(ByteString.copyFrom(encodedMessage))
                .setSignature(ByteString.copyFrom(signature))
                .setSeq(seq)
                .addAllReferences(references)
                .setSessionNonce(nonce)
                .build();
        byte[] mac = MacGenerator.generateMac(request, privKey);


        return SafePostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMessage(ByteString.copyFrom(encodedMessage))
                .setSignature(ByteString.copyFrom(signature))
                .addAllReferences(references)
                .setMac(ByteString.copyFrom(mac))
                .setSeq(seq)
                .setSessionNonce(nonce)
                .build();
    }

    public static SafePostReply generatePostReply(PrivateKey privateKey, String sessionNonce, long seq) throws GeneralSecurityException, IOException {
        byte[] mac = MacGenerator.generateMac(sessionNonce, seq, privateKey);
        return SafePostReply.newBuilder()
                .setSessionNonce(sessionNonce)
                .setSeq(seq)
                .setMac(ByteString.copyFrom(mac))
                .build();
    }

    public static GoodByeRequest generateGoodbyeRequest(PrivateKey privateKey, String sessionNonce, long seq) throws GeneralSecurityException, IOException {
        byte[] mac = MacGenerator.generateMac(sessionNonce, seq, privateKey);
        return GoodByeRequest.newBuilder()
                .setSeq(seq)
                .setSessionNonce(sessionNonce)
                .setMac(ByteString.copyFrom(mac))
                .build();
    }

    public static SafeRegisterRequest generateRegisterRequest(String sessionNonce, long seq, PublicKey pubKey, PrivateKey privKey) throws IOException, GeneralSecurityException {
        return SafeRegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(sessionNonce, seq, pubKey, privKey)))
                .setSessionNonce(sessionNonce)
                .setSeq(seq)
                .build();
    }

    public static SafeRegisterReply generateRegisterReply(String sessionNonce, long seq, PrivateKey privateKey) throws IOException, GeneralSecurityException {
        byte[] replyMac = MacGenerator.generateMac(sessionNonce, seq, privateKey);
        return SafeRegisterReply.newBuilder()
                .setMac(ByteString.copyFrom(replyMac))
                .setSeq(seq)
                .setSessionNonce(sessionNonce)
                .build();
    }

}