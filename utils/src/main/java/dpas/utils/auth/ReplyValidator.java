package dpas.utils.auth;

import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.grpc.contract.Contract;
import io.grpc.StatusRuntimeException;

import java.io.IOException;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class ReplyValidator {

    public static boolean verifySignature(Contract.Announcement announcement, PublicKey authorKey, String boardIdentifier) {
        try {
            var references = Stream.ofNullable(announcement.getReferencesList())
                    .flatMap(List::stream)
                    .collect(Collectors.toSet());
            byte[] messageBytes = Announcement.generateMessageBytes(announcement.getMessage(), references, boardIdentifier, announcement.getSeq());

            Signature sign = Signature.getInstance("SHA256withRSA");
            sign.initVerify(authorKey);
            sign.update(messageBytes);

            if (!sign.verify(announcement.getSignature().toByteArray())) {
                return false;
            }
        } catch (InvalidKeyException | NoSuchAlgorithmException | SignatureException e) {
            return false;
        }
        return true;
    }

    public static boolean verifySignature(Contract.Announcement announcement) {
        try {
            PublicKey authorKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(announcement.getPublicKey().toByteArray()));
            return verifySignature(announcement, authorKey, GeneralBoard.GENERAL_BOARD_IDENTIFIER);
        } catch (GeneralSecurityException e) {
            return false;
        }
    }

    public static boolean validateReadReply(Contract.ReadRequest request, Contract.ReadReply reply, PublicKey serverKey, PublicKey authorKey) {
        try {
            if (!MacVerifier.verifyMac(serverKey, ByteUtils.toByteArray(request), reply.getMac().toByteArray())) {
                return false;
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!ReplyValidator.verifySignature(announcement, authorKey, Base64.getEncoder().encodeToString(authorKey.getEncoded()))) {
                    return false;
                }
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static boolean validateReadGeneralReply(Contract.ReadRequest request, Contract.ReadReply reply, PublicKey serverKey) {
        try {
            if (!MacVerifier.verifyMac(serverKey, ByteUtils.toByteArray(request), reply.getMac().toByteArray())) {
                return false;
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!ReplyValidator.verifySignature(announcement)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean verifyError(StatusRuntimeException e, byte[] request, PublicKey serverKey) {
        if (e.getTrailers() == null) {
            return false;
        }
        var trailers = e.getTrailers();

        if (trailers.get(ErrorGenerator.contentKey) == null) {
            return false;
        }

        if (trailers.get(ErrorGenerator.macKey) == null) {
            return false;
        }

        if (!Arrays.equals(request, trailers.get(ErrorGenerator.contentKey))) {
            return false;
        }

        return MacVerifier.verifyMac(serverKey, e);
    }

    private static boolean verifyError(Throwable t, byte[] request, PublicKey key) {
        if (!(t instanceof  StatusRuntimeException)) {
            return false;
        }
        return verifyError((StatusRuntimeException) t, request, key);
    }

    public static boolean verifyError(Throwable e, Contract.Announcement request, PublicKey serverKey) {
        return verifyError(e, request.getSignature().toByteArray(), serverKey);
    }

    public static boolean verifyError(Throwable e, Contract.ReadRequest request, PublicKey serverKey) {
        return verifyError(e, request.getNonce().getBytes(), serverKey);
    }

    public static boolean verifyError(Throwable e, Contract.RegisterRequest request, PublicKey serverKey) {
        return verifyError(e, request.getMac().toByteArray(), serverKey);
    }
}
