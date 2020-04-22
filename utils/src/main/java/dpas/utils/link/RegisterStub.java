package dpas.utils.link;

import com.google.protobuf.ByteString;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

public class RegisterStub {

    private final QuorumStub _stub;

    private final Map<String, Long> _seqs;

    public RegisterStub(QuorumStub stub) {
        _stub = stub;
        _seqs = new HashMap<>();
    }

    public Contract.Announcement[] read(PublicKey key, int number) throws InterruptedException, GeneralSecurityException {
        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(key.getEncoded()))
                .setNumber(number)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = _stub.read(request);
        if (reply.getAnnouncementsCount() != 0) {
            var announcement = reply.getAnnouncements(reply.getAnnouncementsCount() - 1);
            _stub.post(announcement);
        }
        Contract.Announcement[] announcements = new Contract.Announcement[reply.getAnnouncementsCount()];
        int i = 0;
        for (var a : reply.getAnnouncementsList()) {
            announcements[i] = a;
            i++;
        }
        _seqs.put(Base64.getEncoder().encodeToString(key.getEncoded()), _stub.getSeq(reply.getAnnouncementsList()));
        return announcements;
    }

    public Contract.Announcement[] readGeneral(int number) throws InterruptedException, GeneralSecurityException {
        var request = Contract.ReadRequest.newBuilder()
                .setNumber(number)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = _stub.readGeneral(request);

        Contract.Announcement[] announcements = new Contract.Announcement[reply.getAnnouncementsCount()];
        int i = 0;
        for (var a : reply.getAnnouncementsList()) {
            announcements[i] = a;
            i++;
        }
        return announcements;
    }

    public void post(PublicKey pub, PrivateKey priv, String message, Contract.Announcement[] references)
            throws InterruptedException, GeneralSecurityException, CommonDomainException {
        var seq = getSeq(pub);
        var request = ContractGenerator.generateAnnouncement(pub, priv,
                message, seq, CipherUtils.keyToString(pub), references);
        _stub.post(request);
    }


    public void postGeneral(PublicKey pub, PrivateKey priv, String message, Contract.Announcement[] references)
            throws InterruptedException, GeneralSecurityException, CommonDomainException {
        var req = Contract.ReadRequest.newBuilder()
                .setNumber(1)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var seq = _stub.getSeq(_stub.readGeneral(req).getAnnouncementsList());
        var request = ContractGenerator.generateAnnouncement(pub, priv,
                message, seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, references);
        _stub.postGeneral(request);
    }

    public void register(PublicKey pub, PrivateKey priv) throws InterruptedException, GeneralSecurityException {
        var req = ContractGenerator.generateRegisterRequest(pub, priv);
        _stub.register(req);
    }

    public long getSeq(PublicKey userKey) throws InterruptedException {
        var userId = Base64.getEncoder().encodeToString(userKey.getEncoded());
        if (_seqs.containsKey(userId)) {
            //Don't need read, already know seq from previous read
            var seq = _seqs.get(userId);
            _seqs.put(userId, seq + 1);
            return seq;
        } else {
            //need read, don't know seq from previous read
            var req = Contract.ReadRequest.newBuilder()
                    .setNumber(1)
                    .setPublicKey(ByteString.copyFrom(userKey.getEncoded()))
                    .setNonce(UUID.randomUUID().toString())
                    .build();
            var seq = _stub.getSeq(_stub.read(req).getAnnouncementsList());
            _seqs.put(userId, seq);
            return seq;
        }
    }
}
