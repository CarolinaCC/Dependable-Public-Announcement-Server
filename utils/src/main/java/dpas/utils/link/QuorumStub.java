package dpas.utils.link;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.utils.auth.CipherUtils;
import io.grpc.stub.StreamObserver;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
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

    @Deprecated
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
            }, serverKeys, quorumSize);
        }
        latch.await();

        return replies
                .stream()
                .sorted(Comparator.comparing(a -> -a.getAnnouncementsCount()))
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();
    }


    @Deprecated
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
            }, serverKeys, quorumSize);
        }
        latch.await();
        return replies
                .stream()
                .sorted(Comparator.comparing(a -> -a.getAnnouncementsCount()))
                .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                .get();

    }

    @Deprecated
    public void postGeneralWithException(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        do {
            CountDownLatch latch = new CountDownLatch(quorumSize);
            for (PerfectStub stub : stubs) {
                Announcement a = announcement
                        .toBuilder()
                        .setMessage(CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey()))
                        .build();
                stub.postGeneralWithException(a, new StreamObserver<>() {
                    @Override
                    public synchronized void onNext(Contract.MacReply value) {
                        //Perfect Stub already guarantees the reply is valid
                        serverReply(stub.getServerId(), "OK", replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }

                    @Override
                    public synchronized void onError(Throwable t) {
                        //Perfect Stub already guarantees the reply is valid
                        serverReply(stub.getServerId(), t.getMessage(), replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void onCompleted() {
                    }
                });
            }
            latch.await();
            res = replyCount.entrySet()
                    .stream()
                    .filter(e -> e.getValue() >= quorumSize)
                    .map(Map.Entry::getKey)
                    .findFirst();

        } while (res.isEmpty());
        if (!res.get().equals("OK")) {
            //An exception Occurred
            throw new RuntimeException(res.get());
        }
    }

    @Deprecated
    public void postWithException(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        do {
            CountDownLatch latch = new CountDownLatch(quorumSize);
            for (PerfectStub stub : stubs) {
                Announcement a = announcement
                        .toBuilder()
                        .setMessage(CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey()))
                        .build();
                stub.postWithException(a, new StreamObserver<>() {
                    @Override
                    public synchronized void onNext(Contract.MacReply value) {
                        //Perfect Stub already guarantees the reply is valid
                        serverReply(stub.getServerId(), "OK", replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }

                    @Override
                    public synchronized void onError(Throwable t) {
                        //Perfect Stub already guarantees the reply is valid
                        serverReply(stub.getServerId(), t.getMessage(), replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void onCompleted() {
                    }
                });
            }
            latch.await();
            res = replyCount.entrySet()
                    .stream()
                    .filter(e -> e.getValue() >= quorumSize)
                    .map(Map.Entry::getKey)
                    .findFirst();

        } while (res.isEmpty());
        if (!res.get().equals("OK")) {
            //An exception Occurred
            throw new RuntimeException(res.get());
        }
    }

    @Deprecated
    public Contract.ReadReply readWithException(Contract.ReadRequest request) throws GeneralSecurityException, InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        final List<Contract.ReadReply> readReplies = new ArrayList<>();
        do {
            CountDownLatch latch = new CountDownLatch(quorumSize);
            for (PerfectStub stub : stubs) {
                stub.readWithException(request, new StreamObserver<>() {
                    @Override
                    public synchronized void onNext(Contract.ReadReply value) {
                        //Perfect Stub already guarantees the reply is valid
                        synchronized (readReplies) {
                            readReplies.add(value);
                        }
                        serverReply(stub.getServerId(), "OK", replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }

                    }

                    @Override
                    public synchronized void onError(Throwable t) {
                        //Perfect Stub already guarantees the reply is valid
                        serverReply(stub.getServerId(), t.getMessage(), replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void onCompleted() {
                    }
                });
            }
            latch.await();
            res = replyCount.entrySet()
                    .stream()
                    .filter(e -> e.getValue() >= quorumSize)
                    .map(Map.Entry::getKey)
                    .findFirst();

        } while (res.isEmpty());
        if (!res.get().equals("OK")) {
            //An exception Occurred
            throw new RuntimeException(res.get());
        } else {
            synchronized (readReplies) {
                return readReplies
                        .stream()
                        .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                        .get();
            }
        }
    }

    @Deprecated
    public Contract.ReadReply readGeneralWithException(Contract.ReadRequest request) throws InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        final List<Contract.ReadReply> readReplies = new ArrayList<>();
        do {
            CountDownLatch latch = new CountDownLatch(quorumSize);
            for (PerfectStub stub : stubs) {
                stub.readGeneralWithException(request, new StreamObserver<>() {
                    @Override
                    public synchronized void onNext(Contract.ReadReply value) {
                        //Perfect Stub already guarantees the reply is valid
                        synchronized (readReplies) {
                            readReplies.add(value);
                        }
                        serverReply(stub.getServerId(), "OK", replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }

                    }

                    @Override
                    public synchronized void onError(Throwable t) {
                        //Perfect Stub already guarantees the reply is valid
                        serverReply(stub.getServerId(), t.getMessage(), replies, replyCount);
                        if (latch.getCount() != 0) {
                            latch.countDown();
                        }
                    }

                    @Override
                    public void onCompleted() {
                    }
                });
            }
            latch.await();
            res = replyCount.entrySet()
                    .stream()
                    .filter(e -> e.getValue() >= quorumSize)
                    .map(Map.Entry::getKey)
                    .findFirst();

        } while (res.isEmpty());
        if (!res.get().equals("OK")) {
            //An exception Occurred
            throw new RuntimeException(res.get());
        } else {
            synchronized (readReplies) {
                return readReplies
                        .stream()
                        .max(Comparator.comparing(a -> getSeq(a.getAnnouncementsList())))
                        .get();
            }
        }
    }

    @Deprecated
    public void serverReply(String serverKey, String reply, Map<String, String> replies, Map<String, Integer> replyCount) {
        var prevReply = replies.put(serverKey, reply);
        if (prevReply != null) {
            //Delete previous reply
            replyCount.put(prevReply, replyCount.get(prevReply) - 1);
        }
        if (replyCount.containsKey(reply)) {
            replyCount.put(reply, replyCount.get(reply) + 1);
        } else {
            replyCount.put(reply, 1);
        }
    }

    public long getSeq(List<Announcement> a) {
        if (a.size() == 0) {
            return 0;
        } else {
            return a.get(a.size() - 1).getSeq() + 1;
        }
    }

}
