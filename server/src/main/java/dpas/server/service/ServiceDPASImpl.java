package dpas.server.service;


import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.UserBoard;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.RegisterReply;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.ServiceDPASGrpc;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;

import java.io.UnsupportedEncodingException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static dpas.grpc.contract.Contract.PostStatus.*;
import static dpas.grpc.contract.Contract.RegisterStatus.*;

public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    private ConcurrentHashMap<PublicKey, User> _users = new ConcurrentHashMap<>();
    private GeneralBoard _generalBoard = new GeneralBoard();

    @Override
    public void register(RegisterRequest request, StreamObserver<RegisterReply> replyObserver) {
        Contract.RegisterStatus replyStatus = REGISTERSTATUS_OK;
        try {
            //Get Public Key From byte[]
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            String username = request.getUsername();
            User user = new User(username, key);

            User curr = _users.putIfAbsent(key, user);
            if (curr != null) {
                //User with public key already exists
                replyStatus = REGISTERSTATUS_REPEATED_USER;
            }
        } catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            replyStatus = REGISTERSTATUS_NULL_PUBLICKEY;
        } catch (NullUsernameException e) {
            replyStatus = REGISTERSTATUS_NULL_USERNAME;
        } catch (NullUserException e) {
            //Should Never Happen
            e.printStackTrace();
        }
        replyObserver.onNext(RegisterReply.newBuilder().setStatus(replyStatus).build());
        replyObserver.onCompleted();

    }

    @Override
    public void post(Contract.PostRequest request, StreamObserver<Contract.PostReply> responseObserver) {
        Contract.PostStatus replyStatus = POSTSTATUS_OK;
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = _users.get(key);
            byte[] signature = request.getSignature().toByteArray();
            String message = request.getMessage();
            Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()));

            // post announcement
            user.getUserBoard().post(announcement);

        } catch (InvalidSignatureException | NullSignatureException | SignatureException e) {
            replyStatus = POSTSTATUS_INVALID_SIGNATURE;
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            replyStatus = POSTSATATUS_NULL_PUBLIC_KEY;
        } catch (InvalidMessageSizeException | NullMessageException e) {
            replyStatus = POSTSTATUS_INVALID_MESSAGE_SIZE;
        } catch (NullUserException | InvalidUserException e) {
            replyStatus = POSTSTATUS_NULL_USER;
        } catch (InvalidReferenceException e) {
            replyStatus = POSTSATATUS_INVALID_REFERENCE;
        } catch (UnsupportedEncodingException | NullAnnouncementException e) {
            e.printStackTrace();
        }
        responseObserver.onNext(Contract.PostReply.newBuilder().setStatus(replyStatus).build());
        responseObserver.onCompleted();
    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Contract.PostReply> responseObserver) {
        Contract.PostStatus replyStatus = POSTSTATUS_OK;
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            byte[] signature = request.getSignature().toByteArray();
            String message = request.getMessage();
            Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()));
            synchronized (this) {
                _generalBoard.post(announcement);
            }
        } catch (InvalidSignatureException | NullSignatureException | SignatureException e) {
            replyStatus = POSTSTATUS_INVALID_SIGNATURE;
        } catch (InvalidKeySpecException | InvalidKeyException | NoSuchAlgorithmException e) {
            replyStatus = POSTSATATUS_NULL_PUBLIC_KEY;
        } catch (InvalidMessageSizeException | NullMessageException e) {
            replyStatus = POSTSTATUS_INVALID_MESSAGE_SIZE;
        } catch (NullUserException e) {
            replyStatus = POSTSTATUS_NULL_USER;
        } catch (InvalidReferenceException e) {
            replyStatus = POSTSATATUS_INVALID_REFERENCE;
        } catch (UnsupportedEncodingException | NullAnnouncementException e) {
            e.printStackTrace();
        }
        responseObserver.onNext(Contract.PostReply.newBuilder().setStatus(replyStatus).build());
        responseObserver.onCompleted();
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        Contract.ReadStatus replyStatus = Contract.ReadStatus.READ_OK;

        try {
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(_users.containsKey(key))) {
                replyStatus = Contract.ReadStatus.USER_NOT_REGISTERED;
                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .setStatus(replyStatus)
                        .build());
            } else {
                User user = _users.get(key);
                int numberToRead = request.getNumber();
                UserBoard userBoard = user.getUserBoard();
                ArrayList<Announcement> announcements = userBoard.read(numberToRead);
                byte[] announcementsBytes = SerializationUtils.serialize(announcements);

                responseObserver.onNext(Contract.ReadReply.newBuilder().setAnnouncements(ByteString.copyFrom(announcementsBytes))
                        .setStatus(replyStatus)
                        .build());
            }
        } catch (InvalidNumberOfPostsException | NoSuchAlgorithmException e) {
            replyStatus = Contract.ReadStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION;
            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setStatus(replyStatus)
                    .build());
        } catch (InvalidKeySpecException e) {
            replyStatus = Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION;
            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setStatus(replyStatus)
                    .build());
        }
        responseObserver.onCompleted();
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        Contract.ReadStatus replyStatus = Contract.ReadStatus.READ_OK;

        try {

            int numberToRead = request.getNumber();
            ArrayList<Announcement> announcements = _generalBoard.read(numberToRead);
            byte[] announcementsBytes = SerializationUtils.serialize(announcements);

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setAnnouncements(ByteString.copyFrom(announcementsBytes))
                    .setStatus(replyStatus)
                    .build());
        } catch (InvalidNumberOfPostsException e) {
            replyStatus = Contract.ReadStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION;
            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setStatus(replyStatus)
                    .build());
        }
        responseObserver.onCompleted();
    }


    private ArrayList<Announcement> getListOfReferences(List<Contract.BoardReference> requestReferencesList) throws InvalidReferenceException {
        // add all references to lists of references
        try {
            ArrayList<Announcement> references = new ArrayList<Announcement>();
            for (Contract.BoardReference ref : requestReferencesList) {
                if (ref.hasGeneralBoardReference()) {
                    // find announcement in general board
                    references.add(_generalBoard.getAnnouncementFromReference(ref.getGeneralBoardReference().getSequenceNumber()));
                } else {
                    // find author of reference and get announcement
                    User refUser = _users.get(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(ref.getUserBoardReference().getPublicKey().toByteArray())));
                    if (refUser == null) {
                        throw new InvalidReferenceException();
                    }
                    references.add(refUser.getUserBoard().getAnnouncementFromReference(ref.getUserBoardReference().getSequenceNumber()));
                }
            }
            return references;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new InvalidReferenceException();
        }
    }

}
