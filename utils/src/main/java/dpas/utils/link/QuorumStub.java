package dpas.utils.link;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.utils.auth.CipherUtils;
import io.grpc.stub.StreamObserver;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.CountDownLatch;

public class QuorumStub {
    private final List<PerfectStub> stubs;
    private final int quorumSize;
    private final Map<String, PublicKey> serverKeys;

    public QuorumStub(List<PerfectStub> stubs, int numFaults) {
        this.stubs = stubs;
        this.quorumSize = 2 * numFaults + 1;
        this.serverKeys = new HashMap<>();
        for (var stub : stubs) {
            this.serverKeys.put(stub.getServerId(), stub.getServerKey());
        }
    }


    public void register(Contract.RegisterRequest request) throws InterruptedException {
        final CountDownLatch latch = new CountDownLatch(quorumSize);
        for (PerfectStub stub : stubs) {
            stub.register(request, new StreamObserver<>() {
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

    public void post(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        final CountDownLatch latch = new CountDownLatch(quorumSize);
        for (PerfectStub stub : stubs) {
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
        final CountDownLatch latch = new CountDownLatch(quorumSize);
        for (PerfectStub stub : stubs) {
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

    //Used so that we don't have to generate ready messages for the tests
    public Contract.ReadReply read(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(quorumSize);

        final List<Contract.ReadReply> replies = new ArrayList<>();

        for (PerfectStub stub : stubs) {
            stub.read(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            replies.add(value);
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

        return replies
                .stream()
                .sorted(Comparator.comparing(a -> -a.getAnnouncementsCount()))
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();
    }

    public Contract.ReadReply readReliable(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(quorumSize);

        final List<Contract.ReadReply> replies = new ArrayList<>();

        for (PerfectStub stub : stubs) {
            stub.readReliable(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            replies.add(value);
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
            }, serverKeys, quorumSize);
        }
        latch.await();

        return replies
                .stream()
                .sorted(Comparator.comparing(a -> -a.getAnnouncementsCount()))
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();
    }


    //Used so that we don't have to generate ready messages for the tests
    public Contract.ReadReply readGeneral(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(quorumSize);

        final List<Contract.ReadReply> replies = new ArrayList<>();

        for (PerfectStub stub : stubs) {
            stub.readGeneral(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            replies.add(value);
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
        return replies
                .stream()
                .sorted(Comparator.comparing(a -> -a.getAnnouncementsCount()))
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();

    }

    public Contract.ReadReply readGeneralReliable(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(quorumSize);

        final List<Contract.ReadReply> replies = new ArrayList<>();

        for (PerfectStub stub : stubs) {
            stub.readGeneralReliable(request, new StreamObserver<>() {
                @Override
                public void onNext(Contract.ReadReply value) {
                    //Perfect Stub already guarantees the reply is valid
                    synchronized (latch) {
                        if (latch.getCount() != 0) {
                            replies.add(value);
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
            }, serverKeys, quorumSize);
        }
        latch.await();
        return replies
                .stream()
                .sorted(Comparator.comparing(a -> -a.getAnnouncementsCount()))
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();

    }


    public static long getSeq(List<Announcement> a) {
        if (a.size() == 0) {
            return 0;
        } else {
            return a.get(a.size() - 1).getSeq() + 1;
        }
    }

}
