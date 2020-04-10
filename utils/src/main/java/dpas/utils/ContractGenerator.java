package dpas.utils;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.MacReply;
import dpas.grpc.contract.Contract.PostRequest;
import dpas.grpc.contract.Contract.RegisterRequest;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContractGenerator {

    public static PostRequest generatePostRequest(PublicKey serverKey, PublicKey pubKey, PrivateKey privKey,
                                                  String message, long seq,
                                                  String boardIdentifier, Announcement[] a)
            throws GeneralSecurityException, IOException, CommonDomainException {
        String encodedMessage = CipherUtils.cipherAndEncode(message.getBytes(), serverKey);

        Set<String> references = a == null ? new HashSet<>()
                : Stream.of(a).map(Announcement::getHash).collect(Collectors.toSet());

        byte[] signature = dpas.common.domain.Announcement.generateSignature(privKey, message, references, boardIdentifier);

        byte[] mac = MacGenerator.generateMac(seq, pubKey, encodedMessage, signature, references, privKey);

        return PostRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMessage(encodedMessage)
                .setSignature(ByteString.copyFrom(signature))
                .addAllReferences(references)
                .setMac(ByteString.copyFrom(mac))
                .setSeq(seq)
                .build();
    }

    public static Contract.GetSeqReply generateSeqReply(long seq, String nonce, PrivateKey serverKey, PublicKey pubKey)
            throws IOException, GeneralSecurityException {
        return Contract.GetSeqReply.newBuilder()
                .setSeq(seq)
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(nonce, seq, pubKey, serverKey)))
                .build();
    }


    public static RegisterRequest generateRegisterRequest(PublicKey pubKey, PrivateKey privKey) throws GeneralSecurityException {
        return RegisterRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMac(ByteString.copyFrom(MacGenerator.generateMac(pubKey, privKey)))
                .build();
    }

    public static MacReply generateMacReply(byte[] mac, PrivateKey privateKey) throws GeneralSecurityException {
        byte[] replyMac = MacGenerator.generateMac(mac, privateKey);
        return MacReply.newBuilder()
                .setMac(ByteString.copyFrom(replyMac))
                .build();
    }
}
