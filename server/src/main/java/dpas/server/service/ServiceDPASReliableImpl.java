package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.User;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidSeqException;
import dpas.common.domain.exception.InvalidUserException;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
import dpas.server.persistence.PersistenceManager;
import dpas.server.security.SecurityManager;
import dpas.server.security.exception.IllegalMacException;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.*;
import dpas.utils.link.PerfectStub;
import io.grpc.Context;
import io.grpc.stub.StreamObserver;

import javax.json.JsonObject;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

import static io.grpc.Status.*;

public class ServiceDPASReliableImpl extends ServiceDPASPersistentImpl {
    private final int _quorumSize;
    private final int _numFaults;
    private final String _serverId;
    private final PrivateKey _privateKey;
    private final SecurityManager _securityManager;
    private final List<PerfectStub> _servers;
    private final Map<String, PublicKey> _serverKeys;

    /**
     * Map of echoes sent by current server
     */
    private final Map<String, Boolean> _sentEchos = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> _echosCount = new ConcurrentHashMap<>();


    /**
     * Map of echoes sent by current server
     */
    private final Map<String, Boolean> _sentReadies = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> _readyCount = new ConcurrentHashMap<>();
    private final Map<String, Set<Contract.ReadyAnnouncement>> _announcementProofs = new ConcurrentHashMap<>();

    /**
     * Map of messages delivered
     */
    private final Map<String, CountDownLatch> _deliveredMessages = new ConcurrentHashMap<>();


    public ServiceDPASReliableImpl(PersistenceManager manager, PrivateKey privKey, SecurityManager securityManager, List<PerfectStub> servers, String serverId, int numFaults) {
        super(manager);
        _privateKey = privKey;
        _securityManager = securityManager;
        _serverId = serverId;
        _servers = servers;
        _serverKeys = new HashMap<>();
        for (var stub : servers) {
            _serverKeys.put(stub.getServerId(), stub.getServerKey());
        }
        _quorumSize = 2 * numFaults + 1;
        _numFaults = numFaults;
    }

    //Use with tests only
    public ServiceDPASReliableImpl(PrivateKey privKey, SecurityManager securityManager, List<PerfectStub> servers, String serverId, int numFaults) {
        super(null);
        _privateKey = privKey;
        _securityManager = securityManager;
        _serverId = serverId;
        _servers = servers;
        _serverKeys = new HashMap<>();
        for (var stub : servers) {
            _serverKeys.put(stub.getServerId(), stub.getServerKey());
        }
        _quorumSize = 2 * numFaults + 1;
        _numFaults = numFaults;
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(_users.containsKey(key))) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User with public key does not exist", request, _privateKey));
            } else {

                var announcements = _users.get(key).getUserBoard().read(request.getNumber());
                var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .addAllAnnouncements(announcementsGRPC)
                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcementsGRPC.size(), _privateKey)))
                        .build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {

        try {
            var announcements = _generalBoard.read(request.getNumber());
            var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .addAllAnnouncements(announcementsGRPC)
                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcementsGRPC.size(), _privateKey)))
                    .build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateRequest(request);
            //to validate the public key
            brbRegister(request);
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();

        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (InterruptedException e) {
            //Should never happen
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        }
    }


    @Override
    public void post(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {

            var announcement = generateAnnouncement(request, _privateKey); //validate request

            brbAnnouncement(request, announcement);

            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (InterruptedException e) {
            //Never happens
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "An Error occurred in the server", request, _privateKey));
        }

    }

    @Override
    public void postGeneral(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, _generalBoard, _privateKey);

            brbAnnouncementGeneral(request, announcement);

            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), _privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (InterruptedException e) {
            //Never happens
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "An Error occurred in the server", request, _privateKey));
        }
    }


    @Override
    public void echoRegister(Contract.EchoRegister request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateRequest(request, _serverKeys);

            var id = request.getRequest().getMac().toStringUtf8();

            //broadcastEchoRegister(request.getRequest());

            _echosCount.putIfAbsent(id, new HashSet<>());
            var echos = _echosCount.get(id);
            synchronized (echos) {
                var notExisted = echos.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //First time seeing this echo
                    if (echos.size() == _quorumSize) {
                        broadcastReadyRegister(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        }
    }

    @Override
    public void readyRegister(Contract.ReadyRegister request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateRequest(request, _serverKeys);

            var id = request.getRequest().getMac().toStringUtf8();

            _readyCount.putIfAbsent(id, new HashSet<>());
            var countSet = _readyCount.get(id);
            synchronized (countSet) {
                var notExisted = countSet.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    if (countSet.size() == _numFaults + 1) {
                        //Amplification Step
                        broadcastReadyRegister(request.getRequest());
                    }
                    if (countSet.size() == _quorumSize) {
                        deliverRegister(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (CommonDomainException e) {
            //This never happens by the security manager
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void echoAnnouncement(Contract.EchoAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateAnnouncement(request, _serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), _privateKey);

            var id = request.getRequest().getSignature().toStringUtf8();

            _echosCount.putIfAbsent(id, new HashSet<>());
            var echos = _echosCount.get(id);
            synchronized (echos) {
                var notExisted = echos.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //First time seeing this echo
                    if (echos.size() == _quorumSize) {
                        broadcastReadyAnnouncement(request.getRequest(), announcement);
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException | CommonDomainException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        }
    }

    @Override
    public void readyAnnouncement(Contract.ReadyAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateAnnouncement(request, _serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), _privateKey);

            var id = request.getRequest().getSignature().toStringUtf8();

            _readyCount.putIfAbsent(id, new HashSet<>());
            var countSet = _readyCount.get(id);
            synchronized (countSet) {
                var notExisted = countSet.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //New Proof
                    _announcementProofs.putIfAbsent(id, new HashSet<>());
                    var proofs = _announcementProofs.get(id);
                    synchronized (proofs) {
                        proofs.add(request);
                    }
                    if (countSet.size() == _numFaults + 1) {
                        //Amplification Step
                        broadcastReadyAnnouncement(request.getRequest(), announcement);
                    }
                    if (countSet.size() == _quorumSize) {
                        deliverAnnouncement(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (GeneralSecurityException e) {
           responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (CommonDomainException e) {
            //This never happens by the security manager
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, _privateKey));
        }
    }

    @Override
    public void echoAnnouncementGeneral(Contract.EchoAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateAnnouncement(request, _serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), _generalBoard, _privateKey);

            var id = request.getRequest().getSignature().toStringUtf8();

            _echosCount.putIfAbsent(id, new HashSet<>());
            var echos = _echosCount.get(id);
            synchronized (echos) {
                var notExisted = echos.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //First time seeing this echo
                    if (echos.size() == _quorumSize) {
                        broadcastReadyAnnouncementGeneral(request.getRequest(), announcement);
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException | CommonDomainException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        }
    }

    @Override
    public void readyAnnouncementGeneral(Contract.ReadyAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            _securityManager.validateAnnouncement(request, _serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), _generalBoard, _privateKey);

            var id = request.getRequest().getSignature().toStringUtf8();

            _readyCount.putIfAbsent(id, new HashSet<>());
            var countSet = _readyCount.get(id);
            synchronized (countSet) {
                var notExisted = countSet.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //New Proof
                    _announcementProofs.putIfAbsent(id, new HashSet<>());
                    var proofs = _announcementProofs.get(id);
                    synchronized (proofs) {
                        proofs.add(request);
                    }
                    if (countSet.size() == _numFaults + 1) {
                        //Amplification Step
                        broadcastReadyAnnouncementGeneral(request.getRequest(), announcement);
                    }
                    if (countSet.size() == _quorumSize) {
                        deliverAnnouncementGeneral(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), _privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, _privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, _privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, _privateKey));
        } catch (CommonDomainException e) {
            //This never happens by the security manager
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, _privateKey));
        }
    }


    //Don't want to save when testing
    private void save(JsonObject object) throws IOException {
        if (_manager != null) {
            _manager.save(object);
        }
    }

    private void broadcastEchoRegister(Contract.RegisterRequest request) throws GeneralSecurityException {
        var curr = _sentEchos.putIfAbsent(request.getMac().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting
            var echo = ContractGenerator.generateEchoRegister(request, _privateKey, _serverId);

            //If we don't do this we get an error because we can't send RPCs from an RPC
            Context ctx = Context.current().fork();
            ctx.run(() -> {
                for (var stub : _servers) {
                    stub.echoRegister(echo, new StreamObserver<>() {
                        @Override
                        public void onNext(MacReply value) {
                        }

                        @Override
                        public void onError(Throwable t) {
                        }

                        @Override
                        public void onCompleted() {
                        }
                    });
                }
            });
        }
    }

    private void broadcastEchoAnnouncement(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException {
        var curr = _sentEchos.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

                for (var stub : _servers) {
                    //Server always send the message ciphered with the receiver's public key
                    var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                    request = request.toBuilder().setMessage(message).build();
                    var echo = ContractGenerator.generateEchoAnnouncement(request, _privateKey, _serverId);
                    //If we don't do this we get an error because we can't send RPCs from an RPC
                    Context ctx = Context.current().fork();
                    ctx.run(() -> {

                    stub.echoAnnouncement(echo, new StreamObserver<>() {
                        @Override
                        public void onNext(MacReply value) {
                        }

                        @Override
                        public void onError(Throwable t) {
                        }

                        @Override
                        public void onCompleted() {
                        }
                    });
                });
            }
        }
    }

    private void broadcastEchoAnnouncementGeneral(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException {
        var curr = _sentEchos.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : _servers) {
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateEchoAnnouncement(request, _privateKey, _serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> {

                    stub.echoAnnouncementGeneral(echo, new StreamObserver<>() {
                        @Override
                        public void onNext(MacReply value) {
                        }

                        @Override
                        public void onError(Throwable t) {
                        }

                        @Override
                        public void onCompleted() {
                        }
                    });
                });
            }
        }
    }


    private void broadcastReadyRegister(Contract.RegisterRequest request) throws GeneralSecurityException {
        var curr = _sentReadies.putIfAbsent(request.getMac().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting
            var ready = ContractGenerator.generateReadyRegister(request, _privateKey, _serverId);
            //If we don't do this we get an error because we can't send RPCs from an RPC
            Context ctx = Context.current().fork();
            ctx.run(() -> {
                for (var stub : _servers) {
                    stub.readyRegister(ready, new StreamObserver<>() {
                        @Override
                        public void onNext(MacReply value) {
                        }

                        @Override
                        public void onError(Throwable t) {
                        }

                        @Override
                        public void onCompleted() {
                        }
                    });
                }
            });
        }
    }

    private void broadcastReadyAnnouncement(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException {
        var curr = _sentReadies.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : _servers) {
                //Server always send the message ciphered with the receiver's public key
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateReadyAnnouncement(request, _privateKey, _serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> {

                    stub.readyAnnouncement(echo, new StreamObserver<>() {
                        @Override
                        public void onNext(MacReply value) {
                        }

                        @Override
                        public void onError(Throwable t) {
                        }

                        @Override
                        public void onCompleted() {
                        }
                    });
                });
            }
        }
    }

    private void broadcastReadyAnnouncementGeneral(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException {
        var curr = _sentReadies.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : _servers) {
                //Server always send the message ciphered with the receiver's public key
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateReadyAnnouncement(request, _privateKey, _serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> {

                    stub.readyAnnouncementGeneral(echo, new StreamObserver<>() {
                        @Override
                        public void onNext(MacReply value) {
                        }

                        @Override
                        public void onError(Throwable t) {
                        }

                        @Override
                        public void onCompleted() {
                        }
                    });
                });
            }
        }
    }

    private void deliverRegister(Contract.RegisterRequest request) throws GeneralSecurityException, CommonDomainException, IOException {
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        User user = new User(pubKey);
        var curr = _users.putIfAbsent(pubKey, user);
        if (curr == null) {
            save(user.toJson());
        }
        _deliveredMessages.putIfAbsent(request.getMac().toStringUtf8(), new CountDownLatch(1));
        _deliveredMessages.get(request.getMac().toStringUtf8()).countDown();
    }

    private void deliverAnnouncement(Contract.Announcement request) throws CommonDomainException, GeneralSecurityException, IOException {
        //Is called only one time
        var announcement = generateAnnouncement(request, _privateKey);
        var proofs = _announcementProofs.get(request.getSignature().toStringUtf8());
        synchronized (proofs) {
            for (var proof : proofs) {
                announcement.addProof(proof.getServerKey(), Base64.getEncoder().encodeToString(proof.getMac().toByteArray()));
            }
        }
        _announcements.putIfAbsent(request.getIdentifier(), announcement);
        save(announcement.toJson("Post"));
        announcement.getUser().getUserBoard().post(announcement);
        _deliveredMessages.putIfAbsent(request.getIdentifier(), new CountDownLatch(1));
        _deliveredMessages.get(request.getIdentifier()).countDown();

    }

    private void deliverAnnouncementGeneral(Contract.Announcement request) throws GeneralSecurityException, CommonDomainException, IOException {
        //Is called only one time
        var announcement = generateAnnouncement(request, _generalBoard, _privateKey);
        var proofs = _announcementProofs.get(request.getSignature().toStringUtf8());
        synchronized (proofs) {
            for (var proof : proofs) {
                announcement.addProof(proof.getServerKey(), Base64.getEncoder().encodeToString(proof.getMac().toByteArray()));
            }
        }
        _announcements.putIfAbsent(request.getIdentifier(), announcement);
        save(announcement.toJson("PostGeneral"));
        _generalBoard.post(announcement);
        _deliveredMessages.putIfAbsent(request.getIdentifier(), new CountDownLatch(1));
        _deliveredMessages.get(request.getIdentifier()).countDown();
    }


    private void brbRegister(Contract.RegisterRequest request) throws GeneralSecurityException, InterruptedException {
        broadcastEchoRegister(request); //Received Message start RBR Echo
        _deliveredMessages.putIfAbsent(request.getMac().toStringUtf8(), new CountDownLatch(1));
        _deliveredMessages.get(request.getMac().toStringUtf8()).await();
    }

    private void brbAnnouncement(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException, InterruptedException {
        var curr = _deliveredMessages.putIfAbsent(request.getIdentifier(), new CountDownLatch(1));
        if (curr == null) {
            broadcastEchoAnnouncement(request, announcement); //Received Message start RBR Echo
        }
        _deliveredMessages.get(request.getIdentifier()).await();

    }

    private void brbAnnouncementGeneral(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException, InterruptedException {
        var curr = _deliveredMessages.putIfAbsent(request.getIdentifier(), new CountDownLatch(1));
        if (curr == null) {
            broadcastEchoAnnouncementGeneral(request, announcement); //Received Message start RBR Echo
        }
        _deliveredMessages.get(request.getIdentifier()).await();
    }


    protected Announcement generateAnnouncement(Contract.Announcement request, AnnouncementBoard board, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey));
        if (request.getSeq() > board.getSeq() + 1) {
            //Invalid Seq (General Board is a (N,N) register so it can't be higher than curr + 1
            throw new InvalidSeqException("Invalid seq");
        }

        if (!MacVerifier.verifySeq(request.getSeq(), request.getPublicKey().toByteArray(),
                board.getIdentifier(), request.getIdentifier())) {
            throw new InvalidSeqException("Invalid identifier");
        }

        return new Announcement(signature, _users.get(key), message, getReferences(request.getReferencesList()), board, request.getSeq());
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey));

        User user = _users.get(key);
        if (user == null) {
            throw new InvalidUserException("User does not exist");
        }
        if (request.getSeq() > user.getUserBoard().getSeq() + 1) {
            //Invalid Seq (User Board is a (1,N) register so it must be curr + 1 (or a past one that is repeated)
            throw new InvalidSeqException("Invalid seq");
        }

        if (!MacVerifier.verifySeq(request.getSeq(), request.getPublicKey().toByteArray(),
                Base64.getEncoder().encodeToString(request.getPublicKey().toByteArray()), request.getIdentifier())) {
            throw new InvalidSeqException("Invalid identifier");
        }

        return new Announcement(signature, user, message, getReferences(request.getReferencesList()), user.getUserBoard(), request.getSeq());
    }
}