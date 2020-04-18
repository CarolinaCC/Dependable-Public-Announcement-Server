package dpas.utils.link;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.utils.auth.CipherUtils;
import io.grpc.stub.StreamObserver;

import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.concurrent.CountDownLatch;

public class QuorumStub {
    private final List<PerfectStub> _stubs;
    private final int _numFaults;

    public QuorumStub(List<PerfectStub> stubs, int numFaults) {
        _stubs = stubs;
        _numFaults = numFaults;
    }

    public void post(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        final CountDownLatch latch = new CountDownLatch(2 * _numFaults + 1);
        for (PerfectStub stub : _stubs) {
            Announcement a = announcement
                    .toBuilder()
                    .setMessage(CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey()))
                    .build();
            stub.post(a, new StreamObserver<>() {
                @Override
                public void onNext(Contract.MacReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    public void postGeneral(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        final CountDownLatch latch = new CountDownLatch(2 * _numFaults + 1);
        for (PerfectStub stub : _stubs) {
            Announcement a = announcement
                    .toBuilder()
                    .setMessage(CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey()))
                    .build();
            stub.postGeneral(a, new StreamObserver<>() {
                @Override
                public void onNext(Contract.MacReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();
    }

    public Contract.ReadReply read(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(2 * _numFaults + 1);

        final List<Contract.ReadReply> replies = new ArrayList<>();

        for (PerfectStub stub : _stubs) {
            stub.read(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            latch.countDown();
                            replies.add(value);
                        }
                    }
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();

        return replies
                .stream()
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();
    }


    public Contract.ReadReply readGeneral(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(2 * _numFaults + 1);

        final List<Contract.ReadReply> replies = new ArrayList<>();

        for (PerfectStub stub : _stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            latch.countDown();
                            replies.add(value);
                        }
                    }
                }

                @Override
                public void onError(Throwable t) {
                }

                @Override
                public void onCompleted() {
                }
            });
        }
        latch.await();

        return replies
                .stream()
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();
    }


    public long getSeq(List<Announcement> a) {
        if (a.size() == 0) {
            return 0;
        } else {
            return a.get(a.size() - 1).getSeq() + 1;
        }
    }

}
