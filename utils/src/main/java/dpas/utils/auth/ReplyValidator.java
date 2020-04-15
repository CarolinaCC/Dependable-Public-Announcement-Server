package dpas.utils.auth;

import dpas.grpc.contract.Contract;
import io.grpc.StatusRuntimeException;

import java.io.IOException;
import java.security.*;
import java.util.Arrays;
import java.util.Base64;

public class ReplyValidator {

    public static boolean validateReadReply(Contract.ReadRequest request, Contract.ReadReply reply, PublicKey serverKey, PublicKey authorKey) {
        try {
            if (!MacVerifier.verifyMac(serverKey, ByteUtils.toByteArray(request, reply.getAnnouncementsCount()), reply.getMac().toByteArray())) {
                return false;
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!MacVerifier.verifySignature(announcement, authorKey, Base64.getEncoder().encodeToString(authorKey.getEncoded()))) {
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
            if (!MacVerifier.verifyMac(request, reply, serverKey)) {
                return false;
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!MacVerifier.verifySignature(announcement)) {
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
