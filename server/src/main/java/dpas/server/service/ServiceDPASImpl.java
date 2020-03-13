package dpas.server.service;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.grpc.contract.Contract.RegisterRequest;
import dpas.grpc.contract.Contract.RegisterReply;
import io.grpc.stub.StreamObserver;

public class ServiceDPASImpl extends ServiceDPASGrpc.ServiceDPASImplBase {

    @Override
    public void register(RegisterRequest request, StreamObserver<RegisterReply> replyObserver) {

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
