package dpas.utils.link;

import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.StreamObserver;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;

public class QuorumStub {
    private final List<PerfectStub> _stubs;
    private final int _numFaults;
    private final int _quorumSize;
    public QuorumStub(List<PerfectStub> stubs, int numFaults) {
        _stubs = stubs;
        _numFaults = numFaults;
        _quorumSize = 2 * _numFaults + 1;
    }

    public void post(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        final CountDownLatch latch = new CountDownLatch(_quorumSize);
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
                public void onError(Throwable t) {}

                @Override
                public void onCompleted() {}
            });
        }
        latch.await();
    }

    public void postGeneralWithException(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        do {
            CountDownLatch latch = new CountDownLatch(_quorumSize);
            for (PerfectStub stub : _stubs) {
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
                    .filter(e -> e.getValue() >= _quorumSize)
                    .map(Map.Entry::getKey)
                    .findFirst();

        } while (res.isEmpty());
        if (!res.get().equals("OK")) {
            //An exception Occurred
            throw new RuntimeException(res.get());
        }
    }


    public void postWithException(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        do {
            CountDownLatch latch = new CountDownLatch(_quorumSize);
            for (PerfectStub stub : _stubs) {
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
                    .filter(e -> e.getValue() >= _quorumSize)
                    .map(Map.Entry::getKey)
                    .findFirst();

        } while (res.isEmpty());
        if (!res.get().equals("OK")) {
            //An exception Occurred
            throw new RuntimeException(res.get());
        }
    }

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


    public void postGeneral(Announcement announcement) throws GeneralSecurityException, InterruptedException {
        final CountDownLatch latch = new CountDownLatch(_quorumSize);
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

        final CountDownLatch latch = new CountDownLatch(_quorumSize);

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

    public Contract.ReadReply readWithException(Contract.ReadRequest request) throws GeneralSecurityException, InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        final List<Contract.ReadReply> readReplies = new ArrayList<>();
        do {
            CountDownLatch latch = new CountDownLatch(_quorumSize);
            for (PerfectStub stub : _stubs) {
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
                    .filter(e -> e.getValue() >= _quorumSize)
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

    public Contract.ReadReply readGeneralWithException(Contract.ReadRequest request) throws InterruptedException {
        Map<String, String> replies = new ConcurrentHashMap<>();
        Map<String, Integer> replyCount = new ConcurrentHashMap<>();
        Optional<String> res;
        final List<Contract.ReadReply> readReplies = new ArrayList<>();
        do {
            CountDownLatch latch = new CountDownLatch(_quorumSize);
            for (PerfectStub stub : _stubs) {
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
                    .filter(e -> e.getValue() >= _quorumSize)
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


    public Contract.ReadReply readGeneral(Contract.ReadRequest request) throws InterruptedException {

        final CountDownLatch latch = new CountDownLatch(_quorumSize);

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
