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
import dpas.grpc.contract.Contract.RegisterReplyOrBuilder;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.Contract.RegisterReply;
import io.grpc.stub.StreamObserver;
import org.apache.commons.lang3.SerializationUtils;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;

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


    }

    @Override
    public void postGeneral(Contract.PostRequest request, StreamObserver<Contract.PostReply> responseObserver) {
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            Contract.ReadStatus replyStatus = Contract.ReadStatus.READ_OK;

            PublicKey key = KeyFactory.getInstance("RSA")
                    .generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (key == null) {

                replyStatus = Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION;
                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .setStatus(replyStatus)
                        .build());
            }

            else if(!(_users.containsKey(key))){

                replyStatus = Contract.ReadStatus.USER_NOT_REGISTERED;
                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .setStatus(replyStatus)
                        .build());
            }

            else {
                User user = _users.get(key);
                int numberToRead = request.getNumber();
                UserBoard userBoard = user.getUserBoard();
                ArrayList<Announcement> announcements = userBoard.read(numberToRead);
                byte[] announcementsBytes = SerializationUtils.serialize(announcements);

                responseObserver.onNext(Contract.ReadReply.newBuilder().setAnnouncements(ByteString.copyFrom(announcementsBytes))
                        .setStatus(replyStatus)
                        .build());
            }

        }  catch (InvalidNumberOfPostsException | NoSuchAlgorithmException e) {
                responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setStatus(Contract.ReadStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION)
                    .build());

        } catch (InvalidKeySpecException e) {
            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .setStatus(Contract.ReadStatus.NULL_PUBLIC_KEY_EXCEPTION)
                    .build());
        }

        responseObserver.onCompleted();
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            Contract.ReadStatus replyStatus = Contract.ReadStatus.READ_OK;

            int numberToRead = request.getNumber();
            ArrayList<Announcement> announcements = _generalBoard.read(numberToRead);
            byte[] announcementsBytes = SerializationUtils.serialize(announcements);

            responseObserver.onNext(Contract.ReadReply.newBuilder().setAnnouncements(ByteString.copyFrom(announcementsBytes))
                    .setStatus(replyStatus)
                    .build());

        } catch (InvalidNumberOfPostsException e) {
            Contract.ReadReply.newBuilder().setStatus(Contract.ReadStatus.INVALID_NUMBER_OF_POSTS_EXCEPTION).build();
        }

        responseObserver.onCompleted();
    }

}
