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
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

public class RegisterStub {

    private final QuorumStub stub;

    private final Map<String, Long> seqs;

    public RegisterStub(QuorumStub stub) {
        this.stub = stub;
        this.seqs = new ConcurrentHashMap<>();
    }

    public Contract.Announcement[] read(PublicKey key, int number) throws InterruptedException, GeneralSecurityException {
        var request = Contract.ReadRequest.newBuilder()
                .setPublicKey(ByteString.copyFrom(key.getEncoded()))
                .setNumber(number)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = stub.readReliable(request);

        //Write-Back
        writeBack(reply);

        seqs.put(Base64.getEncoder().encodeToString(key.getEncoded()), QuorumStub.getSeq(reply.getAnnouncementsList()));
        return reply.getAnnouncementsList().toArray(new Contract.Announcement[0]);
    }

    public void writeBack(Contract.ReadReply reply) throws GeneralSecurityException, InterruptedException {
        if (reply.getAnnouncementsCount() != 0) {
            var announcement = reply.getAnnouncements(reply.getAnnouncementsCount() - 1);
            stub.post(announcement);
        }
    }

    public Contract.Announcement[] readGeneral(int number) throws InterruptedException {
        var request = Contract.ReadRequest.newBuilder()
                .setNumber(number)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var reply = stub.readGeneralReliable(request);

        return reply.getAnnouncementsList().toArray(new Contract.Announcement[0]);
    }

    public void post(PublicKey pub, PrivateKey priv, String message, Contract.Announcement[] references)
            throws InterruptedException, GeneralSecurityException, CommonDomainException {
        var seq = getSeq(pub);
        var request = ContractGenerator.generateAnnouncement(pub, priv, message, seq, CipherUtils.keyToString(pub), references);
        stub.post(request);
    }


    public void postGeneral(PublicKey pub, PrivateKey priv, String message, Contract.Announcement[] references)
            throws InterruptedException, GeneralSecurityException, CommonDomainException {
        var req = Contract.ReadRequest.newBuilder()
                .setNumber(1)
                .setNonce(UUID.randomUUID().toString())
                .build();
        var seq = QuorumStub.getSeq(stub.readGeneralReliable(req).getAnnouncementsList());
        var request = ContractGenerator.generateAnnouncement(pub, priv, message, seq, GeneralBoard.GENERAL_BOARD_IDENTIFIER, references);
        stub.postGeneral(request);
    }

    public void register(PublicKey pub, PrivateKey priv) throws InterruptedException, GeneralSecurityException {
        var req = ContractGenerator.generateRegisterRequest(pub, priv);
        stub.register(req);
    }

    public long getSeq(PublicKey userKey) throws InterruptedException {
        var userId = Base64.getEncoder().encodeToString(userKey.getEncoded());
        if (seqs.containsKey(userId)) {
            //Don't need read, already know seq from previous read
            return seqs.put(userId, seqs.get(userId) + 1);
        } else {
            //need read, don't know seq from previous read
            var req = Contract.ReadRequest.newBuilder()
                    .setNumber(1)
                    .setPublicKey(ByteString.copyFrom(userKey.getEncoded()))
                    .setNonce(UUID.randomUUID().toString())
                    .build();
            var seq = QuorumStub.getSeq(stub.readReliable(req).getAnnouncementsList());
            seqs.put(userId, seq + 1);
            return seq;
        }
    }
}
