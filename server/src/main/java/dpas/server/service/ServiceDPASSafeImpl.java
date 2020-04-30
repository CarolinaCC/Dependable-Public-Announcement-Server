package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidSeqException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
import dpas.server.persistence.PersistenceManager;
import dpas.server.security.SecurityManager;
import dpas.server.security.exception.IllegalMacException;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.auth.MacGenerator;
import dpas.utils.auth.MacVerifier;
import io.grpc.stub.StreamObserver;

import javax.json.JsonObject;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Collectors;

import static dpas.common.domain.constants.CryptographicConstants.ASYMMETRIC_KEY_ALGORITHM;
import static dpas.common.domain.constants.JsonConstants.POST_GENERAL_OP_TYPE;
import static dpas.common.domain.constants.JsonConstants.POST_OP_TYPE;
import static io.grpc.Status.*;

/**
 * (Using ReliableImpl for the second delivery instead), maintained so we don't have to generate READY messages when testing
 */
@Deprecated
public class ServiceDPASSafeImpl extends ServiceDPASPersistentImpl {
    private final PrivateKey privateKey;

    public ServiceDPASSafeImpl(PersistenceManager manager, PrivateKey privKey) {
        super(manager);
        this.privateKey = privKey;

    }

    //Use with tests only
    public ServiceDPASSafeImpl(PrivateKey privKey) {
        super(null);
        this.privateKey = privKey;
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(users.containsKey(key))) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User with public key does not exist", request, privateKey));
            } else {

                var announcements = users.get(key).getUserBoard().read(request.getNumber());
                var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .addAllAnnouncements(announcementsGRPC)
                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcementsGRPC.size(), privateKey)))
                        .build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            var announcements = generalBoard.read(request.getNumber());
            var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .addAllAnnouncements(announcementsGRPC)
                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcementsGRPC.size(), privateKey)))
                    .build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        }
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateRequest(request);

            PublicKey pubKey = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = new User(pubKey);
            var curr = users.putIfAbsent(pubKey, user);
            if (curr == null) {
                save(user.toJson());
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();

        } catch (CommonDomainException | IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        }
    }


    @Override
    public void post(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, privateKey);

            var curr = announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr == null) {
                //Announcement with that identifier does not exist yet
                save(announcement.toJson(POST_OP_TYPE));
                announcement.getUser().getUserBoard().post(announcement);
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        }

    }

    @Override
    public void postGeneral(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, generalBoard, privateKey);

            var curr = announcements.putIfAbsent(announcement.getIdentifier(), announcement);
            if (curr == null) {
                //Announcement with that identifier does not exist yet
                save(announcement.toJson(POST_GENERAL_OP_TYPE));
                generalBoard.post(announcement);
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        }
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, AnnouncementBoard board, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey));
        if (request.getSeq() > board.getSeq() + 1) {
            //Invalid Seq (General Board is a (N,N) register so it can't be higher than curr + 1
            throw new InvalidSeqException("Invalid seq");
        }

        if (!MacVerifier.verifySeq(request.getSeq(), request.getPublicKey().toByteArray(),
                board.getIdentifier(), request.getIdentifier())) {
            throw new InvalidSeqException("Invalid identifier");
        }

        return new Announcement(signature, users.get(key), message, getReferences(request.getReferencesList()), board, request.getSeq());
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey));

        User user = users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        if (request.getSeq() > user.getUserBoard().getSeq() + 1) {
            //Invalid Seq (User Board is a (1,N) register so it must be curr + 1 (or a past one that is repeated)
            throw new InvalidSeqException("Invalid seq");
        }

        if (!MacVerifier.verifySeq(request.getSeq(), request.getPublicKey().toByteArray(),
                Base64.getEncoder().encodeToString(request.getPublicKey().toByteArray()), request.getIdentifier())) {
            throw new InvalidSeqException("Invalid identifier");
        }

        return new Announcement(signature, user, message, getReferences(request.getReferencesList()), user.getUserBoard(), request.getSeq());
    }


    //Don't want to save when testing
    private void save(JsonObject object) throws IOException {
        if (manager != null) {
            manager.save(object);
        }
    }
}