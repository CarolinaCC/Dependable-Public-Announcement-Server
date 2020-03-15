package dpas.server.service;


import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.UserBoard;
import dpas.common.domain.exception.InvalidNumberOfPostsException;

import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.Contract.RegisterReply;
import io.grpc.stub.StreamObserver;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

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
        }
        catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
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
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            User user = _users.get(key);
            byte[] signature = request.getSignature().toByteArray();
            String message = request.getMessage().toString();
            Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()));

            // post announcement
            user.getUserBoard().post(announcement);

        } catch (InvalidSignatureException | NullSignatureException | SignatureException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_INVALID_SIGNATURE)
                    .build());
        } catch (NullAnnouncementException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_NULL_ANNOUNCEMENT)
                    .build());
        } catch (InvalidMessageSizeException | NullMessageException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_INVALID_MESSAGE_SIZE)
                    .build());
        } catch (NullUserException | InvalidUserException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_NULL_USER)
                    .build());
        } catch (InvalidReferenceException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSATATUS_INVALID_REFERENCE)
                    .build());
        } catch (Exception e) {
            e.printStackTrace();
        }
        responseObserver.onCompleted();
    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Contract.PostReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            byte[] signature = request.getSignature().toByteArray();
            String message = request.getMessage().toString();
            Announcement announcement = new Announcement(signature, _users.get(key), message, getListOfReferences(request.getReferencesList()));

            synchronized (this) {
                _generalBoard.post(announcement);
            }

        } catch (InvalidSignatureException | NullSignatureException | SignatureException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_INVALID_SIGNATURE)
                    .build());
        } catch (NullAnnouncementException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_NULL_ANNOUNCEMENT)
                    .build());
        } catch (InvalidMessageSizeException | NullMessageException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_INVALID_MESSAGE_SIZE)
                    .build());
        } catch (NullUserException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSTATUS_NULL_USER)
                    .build());
        } catch (InvalidReferenceException e) {
            responseObserver.onNext(Contract.PostReply.newBuilder()
                    .setStatus(Contract.PostStatus.POSTSATATUS_INVALID_REFERENCE)
                    .build());
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            User user = _users.get(key);
            int numberToRead = request.getNumber();
            UserBoard userBoard = user.getUserBoard();
            ArrayList<Announcement> announcements = userBoard.read(numberToRead);

            String announcementsString = announcements.stream().map(Announcement::toString)
                    .collect(Collectors.joining("|| "));

            Contract.ReadReply.newBuilder().setAnnouncements(0, announcementsString)
                    .setStatus(Contract.readStatus.READ_OK)
                    .build();

        }  catch (InvalidNumberOfPostsException | NoSuchAlgorithmException | InvalidKeySpecException e) {
            Contract.ReadReply.newBuilder()
                    .setStatus(Contract.readStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION)
                    .build();
        }

        responseObserver.onCompleted();
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            int numberToRead = request.getNumber();
            ArrayList<Announcement> announcements = _generalBoard.read(numberToRead);
            String announcementsString = announcements.stream().map(Announcement::toString).collect(Collectors.joining("|| "));

            Contract.ReadReply.newBuilder().setAnnouncements(0, announcementsString).setStatus(Contract.readStatus.READ_OK).build();

        } catch (InvalidNumberOfPostsException e) {
            Contract.ReadReply.newBuilder().setStatus(Contract.readStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION).build();
        }

        responseObserver.onCompleted();
    }


    private ArrayList<Announcement> getListOfReferences(List<Contract.BoardReference> requestReferencesList) throws InvalidReferenceException, NoSuchAlgorithmException, InvalidKeySpecException {
        // add all references to lists of references
        ArrayList<Announcement> references = new ArrayList<Announcement>();
        for (Contract.BoardReference ref : requestReferencesList) {
            if (ref.hasGeneralBoardReference()) {
                // find announcement in general board
                references.add(_generalBoard.getAnnouncementFromReference(ref.getGeneralBoardReference().getSequenceNumber()));
            } else {
                // find author of reference and get announcement
                User refUser = _users.get(KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(ref.getUserBoardReference().getPublicKey().toByteArray())));
                references.add(refUser.getUserBoard().getAnnouncementFromReference(ref.getUserBoardReference().getSequenceNumber()));
            }
        }
        return references;
    }

}
