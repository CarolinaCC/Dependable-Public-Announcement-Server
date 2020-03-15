package dpas.server.service;

import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.NullPublicKeyException;
import dpas.common.domain.exception.NullUserException;
import dpas.common.domain.exception.NullUsernameException;
import dpas.common.domain.exception.UserAlreadyExistsException;
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
import java.util.concurrent.ConcurrentHashMap;

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

            //User with public key already exists
            if (curr != null) {
                replyObserver.onNext(RegisterReply.newBuilder()
                        .setStatus(Contract.RegisterStatus.REGISTERSTATUS_REPEATED_USER)
                        .build());
            } else {
                replyObserver.onNext(RegisterReply.newBuilder()
                        .setStatus(Contract.RegisterStatus.REGISTERSTATUS_OK)
                        .build());
            }
        } catch (NullPublicKeyException e) {
            replyObserver.onNext(RegisterReply.newBuilder()
                    .setStatus(Contract.RegisterStatus.REGISTERSTATUS_NULL_PUBLICKEY)
                    .build());
        } catch (NullUsernameException e) {
            replyObserver.onNext(RegisterReply.newBuilder()
                    .setStatus(Contract.RegisterStatus.REGISTERSTATUS_NULL_USERNAME)
                    .build());

        } catch (InvalidKeySpecException | NoSuchAlgorithmException |
                NullUserException e) {
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
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
    }
}
