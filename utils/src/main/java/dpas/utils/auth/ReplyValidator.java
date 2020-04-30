package dpas.utils.auth;

import dpas.grpc.contract.Contract;
import dpas.utils.Constants;
import org.apache.commons.lang3.ArrayUtils;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public final class ReplyValidator {

    private ReplyValidator() {
    }

    public static boolean validateReadReply(Contract.ReadRequest request, Contract.ReadReply reply, PublicKey serverKey,
                                            PublicKey authorKey, Map<String, PublicKey> serverKeys, int quorumSize) {
        try {
            Set<String> seen = new HashSet<>();
            if (!MacVerifier.verifyMac(serverKey, ByteUtils.toByteArray(request, reply.getAnnouncementsCount()), reply.getMac().toByteArray())) {
                return false;
            }

            if (request.getNumber() != 0) {
                if (reply.getAnnouncementsCount() > request.getNumber()) {
                    return false;
                }
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!MacVerifier.verifySignature(announcement, authorKey, Base64.getEncoder().encodeToString(authorKey.getEncoded()))) {
                    return false;
                }
                if (seen.contains(announcement.getIdentifier())) {
                    return false;
                }
                seen.add(announcement.getIdentifier());
                if (!validateProofs(announcement, serverKeys, quorumSize)) {
                    return false;
                }
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static boolean validateReadGeneralReply(Contract.ReadRequest request, Contract.ReadReply reply,
                                                   PublicKey serverKey, Map<String, PublicKey> serverKeys, int quorumSize) {
        try {
            Set<String> seen = new HashSet<>();
            if (!MacVerifier.verifyMac(request, reply, serverKey)) {
                return false;
            }

            if (request.getNumber() != 0) {
                if (reply.getAnnouncementsCount() > request.getNumber()) {
                    return false;
                }
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!MacVerifier.verifySignature(announcement)) {
                    return false;
                }
                if (seen.contains(announcement.getIdentifier())) {
                    return false;
                }
                seen.add(announcement.getIdentifier());
                if (!validateProofs(announcement, serverKeys, quorumSize)) {
                    return false;
                }
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public static boolean validateProofs(Contract.Announcement announcement, Map<String, PublicKey> serverKeys, int quorumSize) {
        var proofs = announcement.getReadyProofMap();

        if (proofs.size() < quorumSize) {
            return false;
        }

        for (var entry : proofs.entrySet()) {
            var serverId = entry.getKey();
            PublicKey pubKey = serverKeys.get(serverId);
            if (pubKey == null) {
                return false;
            }
            var content = ArrayUtils.addAll(announcement.getSignature().toByteArray(), Constants.READY);
            var mac = Base64.getDecoder().decode(entry.getValue());
            if (!MacVerifier.verifyMac(pubKey, content, mac)) {
                return false;
            }
        }
        return true;
    }


    public static boolean validateReadReply(Contract.ReadRequest request, Contract.ReadReply reply, PublicKey serverKey, PublicKey authorKey) {
        try {
            Set<String> seen = new HashSet<>();
            if (!MacVerifier.verifyMac(serverKey, ByteUtils.toByteArray(request, reply.getAnnouncementsCount()), reply.getMac().toByteArray())) {
                return false;
            }

            if (request.getNumber() != 0) {
                if (reply.getAnnouncementsCount() > request.getNumber()) {
                    return false;
                }
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!MacVerifier.verifySignature(announcement, authorKey, Base64.getEncoder().encodeToString(authorKey.getEncoded()))) {
                    return false;
                }
                if (seen.contains(announcement.getIdentifier())) {
                    return false;
                }
                seen.add(announcement.getIdentifier());
            }
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    public static boolean validateReadGeneralReply(Contract.ReadRequest request, Contract.ReadReply reply, PublicKey serverKey) {
        try {
            Set<String> seen = new HashSet<>();
            if (!MacVerifier.verifyMac(request, reply, serverKey)) {
                return false;
            }

            if (request.getNumber() != 0) {
                if (reply.getAnnouncementsCount() > request.getNumber()) {
                    return false;
                }
            }

            for (Contract.Announcement announcement : reply.getAnnouncementsList()) {
                if (!MacVerifier.verifySignature(announcement)) {
                    return false;
                }
                if (seen.contains(announcement.getIdentifier())) {
                    return false;
                }
                seen.add(announcement.getIdentifier());
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }

}
