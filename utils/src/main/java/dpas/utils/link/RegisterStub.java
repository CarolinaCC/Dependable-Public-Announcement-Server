package dpas.utils.link;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.exception.CommonDomainException;
import dpas.grpc.contract.Contract;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Set;
import java.util.UUID;

public class RegisterStub {

    private QuorumStub _stub;

    public RegisterStub(QuorumStub stub) {
        this._stub = stub;
    }

    public Contract.Announcement[] read(PublicKey key, int number) throws InterruptedException, GeneralSecurityException {
        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(key.getEncoded()))
                .setNumber(number)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = _stub.readWithException(request);
        if (reply.getAnnouncementsCount() != 0) {
            var announcement = reply.getAnnouncements(reply.getAnnouncementsCount() - 1);
            _stub.postWithException(announcement);
        }
        Contract.Announcement[] announcements = new Contract.Announcement[reply.getAnnouncementsCount()];
        int i = 0;
        for( var a: reply.getAnnouncementsList()) {
            announcements[i] = a;
            i++;
        }
        return announcements;
    }

    public Contract.Announcement[] readGeneral(int number) throws InterruptedException, GeneralSecurityException {
        var request = Contract.ReadRequest.newBuilder()
                .setNumber(number)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = _stub.readGeneralWithException(request);

        Contract.Announcement[] announcements = new Contract.Announcement[reply.getAnnouncementsCount()];
        int i = 0;
        for( var a: reply.getAnnouncementsList()) {
            announcements[i] = a;
            i++;
        }
        return announcements;
    }

    public void post(PublicKey pub, PrivateKey priv, String message, Contract.Announcement[] references)
            throws InterruptedException, GeneralSecurityException, CommonDomainException {
        var req = Contract.ReadRequest.newBuilder()
                .setNumber(1)
                .setPublicKey(ByteString.copyFrom(pub.getEncoded()))
                .setNonce(UUID.randomUUID().toString())
                .build();
        var seq = _stub.getSeq(_stub.readWithException(req).getAnnouncementsList());
        var request = ContractGenerator.generateAnnouncement(pub, priv,
                message, seq, CipherUtils.keyToString(pub), references);
        _stub.postWithException(request);
    }


    public void postGeneral(PublicKey pub, PrivateKey priv, String message, Contract.Announcement[] references)
            throws InterruptedException, GeneralSecurityException, CommonDomainException {
        var req = Contract.ReadRequest.newBuilder()
                .setNumber(1)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var seq = _stub.getSeq(_stub.readGeneralWithException(req).getAnnouncementsList());
        var request = ContractGenerator.generateAnnouncement(pub, priv,
                message, seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, references);
        _stub.postGeneralWithException(request);
    }

}
