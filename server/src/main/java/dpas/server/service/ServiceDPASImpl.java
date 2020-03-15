package dpas.server.service;


import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.UserBoard;
import dpas.common.domain.exception.InvalidNumberOfPostsException;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.common.domain.exception.UserAlreadyExistsException;
import dpas.common.domain.UserBoard;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.Contract.RegisterReply;
import io.grpc.stub.StreamObserver;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    private ConcurrentHashMap<PublicKey, User> _users = new ConcurrentHashMap<>();
    private GeneralBoard _generalBoard = new GeneralBoard();

    @Override
    public void register(RegisterRequest request, StreamObserver<RegisterReply> replyObserver) {
        try {
            //Get Public Key From byte[]
            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
            String username = request.getUsername();

            User user = new User(username, key);


            User curr = _users.putIfAbsent(key, user);

            if (curr != null) {
                //User with public key already exists
                replyObserver.onNext(RegisterReply.newBuilder()
                        .setStatus(Contract.RegisterStatus.REGISTERSTATUS_REPEATED_USER)
                        .build());
            } else {
                replyObserver.onNext(RegisterReply.newBuilder()
                        .setStatus(Contract.RegisterStatus.REGISTERSTATUS_OK)
                        .build());
            }
        } catch (NullPublicKeyException | InvalidKeySpecException | NoSuchAlgorithmException e) {
            replyObserver.onNext(RegisterReply.newBuilder()
                    .setStatus(Contract.RegisterStatus.REGISTERSTATUS_NULL_PUBLICKEY)
                    .build());

        } catch (NullUsernameException e) {
            replyObserver.onNext(RegisterReply.newBuilder()
                    .setStatus(Contract.RegisterStatus.REGISTERSTATUS_NULL_USERNAME)
                    .build());

        } catch (NullUserException e) {
            e.printStackTrace();
            //Should Never Happen
        }
        replyObserver.onCompleted();

    }

    @Override
    public void post(Contract.PostRequest request, StreamObserver<Contract.PostReply> responseObserver) {


    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Contract.PostReply> responseObserver) {
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

}
