package dpas.utils;

import com.google.protobuf.ByteString;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.grpc.contract.Contract.MacReply;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.MacGenerator;
import io.grpc.StatusRuntimeException;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Base64;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ContractGenerator {

    public static Contract.Announcement generateAnnouncement(PublicKey pubKey, PrivateKey privKey, String message, long seq,
                                                             String boardIdentifier, Announcement[] a)
            throws CommonDomainException {

        Set<String> references = Stream.ofNullable(a)
                .flatMap(Arrays::stream)
                .map(Announcement::getIdentifier)
                .collect(Collectors.toSet());

        byte[] signature = dpas.common.domain.Announcement.generateSignature(privKey, message, references, boardIdentifier, seq);

        return Announcement.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMessage(message)
                .setSignature(ByteString.copyFrom(signature))
                .addAllReferences(references)
                .setSeq(seq)
                .setIdentifier(generateIdentifier(pubKey, seq, boardIdentifier))
                .build();
    }

    public static Announcement generateAnnouncement(PublicKey serverKey, PublicKey pubKey, PrivateKey privKey,
                                                    String message, long seq, String boardIdentifier, Announcement[] a)
            throws GeneralSecurityException, CommonDomainException {

        String encodedMessage = CipherUtils.cipherAndEncode(message.getBytes(), serverKey);

        Set<String> references = Stream.ofNullable(a)
                .flatMap(Arrays::stream)
                .map(Announcement::getIdentifier)
                .collect(Collectors.toSet());

        byte[] signature = dpas.common.domain.Announcement.generateSignature(privKey, message, references, boardIdentifier, seq);

        return Announcement.newBuilder()
                .setPublicKey(ByteString.copyFrom(pubKey.getEncoded()))
                .setMessage(encodedMessage)
                .setSignature(ByteString.copyFrom(signature))
                .addAllReferences(references)
                .setSeq(seq)
                .setIdentifier(generateIdentifier(pubKey, seq, boardIdentifier))
                .build();
    }

    private static String generateIdentifier(PublicKey authorKey, long seq, String boardIdentifier) {
        try {
            var content = new StringBuilder()
                    .append(seq)
                    .append(boardIdentifier)
                    .append(Base64.getEncoder().encodeToString(authorKey.getEncoded()))
                    .toString();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(content.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        }catch (GeneralSecurityException e) {
            //never happens
            return "";
        }

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
