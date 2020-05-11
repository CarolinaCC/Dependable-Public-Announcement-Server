package dpas.server.service;

import com.google.protobuf.ByteString;
import dpas.common.domain.Announcement;
import dpas.common.domain.AnnouncementBoard;
import dpas.common.domain.GeneralBoard;
import dpas.common.domain.User;
import dpas.common.domain.constants.JsonConstants;
import dpas.common.domain.exception.*;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.MacReply;
import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
import dpas.server.security.SecurityManager;
import dpas.server.security.exception.IllegalMacException;
import dpas.utils.ContractGenerator;
import dpas.utils.auth.CipherUtils;
import dpas.utils.auth.ErrorGenerator;
import dpas.utils.auth.MacGenerator;
import dpas.utils.auth.MacVerifier;
import dpas.utils.link.PerfectStub;
import io.grpc.Context;
import io.grpc.stub.StreamObserver;

import javax.json.Json;
import javax.json.JsonObject;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CountDownLatch;
import java.util.stream.Collectors;

import static dpas.common.domain.constants.CryptographicConstants.ASYMMETRIC_KEY_ALGORITHM;
import static dpas.common.domain.constants.JsonConstants.*;
import static io.grpc.Status.*;

public class ServiceDPASReliableImpl extends ServiceDPASGrpc.ServiceDPASImplBase {
    private final int quorumSize;
    private final int numFaults;
    private final String serverId;
    private final PrivateKey privateKey;
    private final List<PerfectStub> servers;
    private final Map<String, PublicKey> serverKeys;
    private final PersistenceManager manager;
    private final ConcurrentHashMap<String, Announcement> announcements;
    private final ConcurrentHashMap<PublicKey, User> users;
    private final GeneralBoard generalBoard;
    private final Set<String> nonces = Collections.synchronizedSet(new HashSet<>());
    private final Map<String, Boolean> echoesSent = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> echosSeen = new ConcurrentHashMap<>();
    private final Map<String, Boolean> readiesSent = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> readiesSeen = new ConcurrentHashMap<>();
    private final Map<String, Set<Contract.ReadyAnnouncement>> announcementProofs = new ConcurrentHashMap<>();
    private final Map<String, CountDownLatch> deliveredMessages = new ConcurrentHashMap<>();

    public ServiceDPASReliableImpl(PersistenceManager manager, PrivateKey privKey, List<PerfectStub> servers, String serverId, int numFaults) {
        this.announcements = new ConcurrentHashMap<>();
        this.users = new ConcurrentHashMap<>();
        this.generalBoard = new GeneralBoard();
        this.manager = manager;
        this.privateKey = privKey;
        this.serverId = serverId;
        this.servers = servers;
        this.serverKeys = new HashMap<>();
        this.servers.forEach(server -> serverKeys.put(server.getServerId(), server.getServerKey()));
        this.quorumSize = 2 * numFaults + 1;
        this.numFaults = numFaults;
    }

    public ServiceDPASReliableImpl(PrivateKey privKey, List<PerfectStub> servers, String serverId, int numFaults) {
        this(null, privKey, servers, serverId, numFaults);
    }

    @Override
    public void read(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            String nonce = request.getNonce();
            if (isReadRepeated(nonce)) {
                responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, "Nonce is repeated", request, privateKey));
                return;
            }
            addNonce(nonce);
            save(readObject(nonce));

            PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));

            if (!(users.containsKey(key))) {
                responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "User with public key does not exist", request, privateKey));
            } else {

                var announcements = users.get(key).getUserBoard().read(request.getNumber());
                var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

                responseObserver.onNext(Contract.ReadReply.newBuilder()
                        .addAllAnnouncements(announcementsGRPC)
                        .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcementsGRPC.size(), privateKey)))
                        .build());
                responseObserver.onCompleted();
            }
        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        }
    }

    @Override
    public void readGeneral(Contract.ReadRequest request, StreamObserver<Contract.ReadReply> responseObserver) {
        try {
            String nonce = request.getNonce();
            if (isReadRepeated(nonce)) {
                responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, "Nonce is repeated", request, privateKey));
                return;
            }
            addNonce(nonce);
            save(readObject(nonce));

            var announcements = generalBoard.read(request.getNumber());
            var announcementsGRPC = announcements.stream().map(Announcement::toContract).collect(Collectors.toList());

            responseObserver.onNext(Contract.ReadReply.newBuilder()
                    .addAllAnnouncements(announcementsGRPC)
                    .setMac(ByteString.copyFrom(MacGenerator.generateMac(request, announcementsGRPC.size(), privateKey)))
                    .build());
            responseObserver.onCompleted();

        } catch (Exception e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        }
    }

    @Override
    public void register(Contract.RegisterRequest request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateRequest(request);
            //to validate the public key
            brbRegister(request);
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();

        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (InterruptedException e) {
            //Should never happen
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        }
    }


    @Override
    public void post(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, privateKey); //validate request
            brbAnnouncement(request, announcement);

            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (InterruptedException e) {
            //Never happens
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "An Error occurred in the server", request, privateKey));
        }

    }

    @Override
    public void postGeneral(Contract.Announcement request, StreamObserver<MacReply> responseObserver) {
        try {
            var announcement = generateAnnouncement(request, generalBoard, privateKey);
            brbAnnouncementGeneral(request, announcement);

            responseObserver.onNext(ContractGenerator.generateMacReply(request.getSignature().toByteArray(), privateKey));
            responseObserver.onCompleted();

        } catch (InvalidSeqException | InvalidUserException e) {
            responseObserver.onError(ErrorGenerator.generate(UNAUTHENTICATED, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (CommonDomainException | IllegalArgumentException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (InterruptedException e) {
            //Never happens
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, "An Error occurred in the server", request, privateKey));
        }
    }


    @Override
    public void echoRegister(Contract.EchoRegister request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateRequest(request, serverKeys);
            var id = request.getRequest().getMac().toStringUtf8();

            Set<String> echos;
            synchronized (echos = echosSeen.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>()))) {
                boolean notExisted = echos.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //First time seeing this echo
                    if (echos.size() == quorumSize) {
                        broadcastReadyRegister(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        }
    }

    @Override
    public void readyRegister(Contract.ReadyRegister request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateRequest(request, serverKeys);

            String id = request.getRequest().getMac().toStringUtf8();

            Set<String> countSet;
            synchronized (countSet = readiesSeen.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>()))) {
                boolean notExisted = countSet.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    if (countSet.size() == numFaults + 1) {
                        //Amplification Step
                        broadcastReadyRegister(request.getRequest());
                    }
                    if (countSet.size() == quorumSize) {
                        deliverRegister(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (CommonDomainException e) {
            //This never happens by the security manager
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, privateKey));
        }
    }

    @Override
    public void echoAnnouncement(Contract.EchoAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateAnnouncement(request, serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), privateKey);

            String id = request.getRequest().getSignature().toStringUtf8();

            Set<String> echos;
            synchronized (echos = echosSeen.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>()))) {
                boolean notExisted = echos.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //First time seeing this echo
                    if (echos.size() == quorumSize) {
                        broadcastReadyAnnouncement(request.getRequest(), announcement);
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException | CommonDomainException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        }
    }

    @Override
    public void readyAnnouncement(Contract.ReadyAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateAnnouncement(request, serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), privateKey);
            String id = request.getRequest().getSignature().toStringUtf8();

            Set<String> countSet;
            synchronized (countSet = readiesSeen.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>()))) {
                boolean notExisted = countSet.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //New Proof
                    announcementProofs.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>())).add(request);

                    if (countSet.size() == numFaults + 1) {
                        //Amplification Step
                        broadcastReadyAnnouncement(request.getRequest(), announcement);
                    }
                    if (countSet.size() == quorumSize) {
                        deliverAnnouncement(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (CommonDomainException e) {
            //This never happens by the security manager
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, privateKey));
        }
    }

    @Override
    public void echoAnnouncementGeneral(Contract.EchoAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateAnnouncement(request, serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), generalBoard, privateKey);
            var id = request.getRequest().getSignature().toStringUtf8();

            Set<String> echos;
            synchronized (echos = echosSeen.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>()))) {
                boolean notExisted = echos.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //First time seeing this echo
                    if (echos.size() == quorumSize) {
                        broadcastReadyAnnouncementGeneral(request.getRequest(), announcement);
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException | CommonDomainException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        }
    }

    @Override
    public void readyAnnouncementGeneral(Contract.ReadyAnnouncement request, StreamObserver<MacReply> responseObserver) {
        try {
            SecurityManager.validateAnnouncement(request, serverKeys);

            var announcement = generateAnnouncement(request.getRequest(), generalBoard, privateKey);
            var id = request.getRequest().getSignature().toStringUtf8();

            Set<String> countSet;
            synchronized (countSet = readiesSeen.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>()))) {
                var notExisted = countSet.add(request.getMac().toStringUtf8());
                if (notExisted) {
                    //New Proof
                    announcementProofs.computeIfAbsent(id, key -> Collections.synchronizedSet(new HashSet<>())).add(request);
                    if (countSet.size() == numFaults + 1) {
                        //Amplification Step
                        broadcastReadyAnnouncementGeneral(request.getRequest(), announcement);
                    }
                    if (countSet.size() == quorumSize) {
                        deliverAnnouncementGeneral(request.getRequest());
                    }
                }
            }
            responseObserver.onNext(ContractGenerator.generateMacReply(request.getMac().toByteArray(), privateKey));
            responseObserver.onCompleted();
        } catch (IllegalMacException e) {
            responseObserver.onError(ErrorGenerator.generate(INVALID_ARGUMENT, e.getMessage(), request, privateKey));
        } catch (IOException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "An Error occurred in the server", request, privateKey));
        } catch (GeneralSecurityException e) {
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, "Invalid security values provided", request, privateKey));
        } catch (CommonDomainException e) {
            //This never happens by the security manager
            responseObserver.onError(ErrorGenerator.generate(CANCELLED, e.getMessage(), request, privateKey));
        }
    }

    private void broadcastEchoRegister(Contract.RegisterRequest request) throws GeneralSecurityException {
        var curr = echoesSent.putIfAbsent(request.getMac().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting
            var echo = ContractGenerator.generateEchoRegister(request, privateKey, serverId);

            //If we don't do this we get an error because we can't send RPCs from an RPC
            Context ctx = Context.current().fork();
            ctx.run(() -> {
                for (var stub : servers) {
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
        var curr = echoesSent.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : servers) {
                //Server always send the message ciphered with the receiver's public key
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateEchoAnnouncement(request, privateKey, serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> stub.echoAnnouncement(echo, new StreamObserver<>() {
                    @Override
                    public void onNext(MacReply value) {
                    }

                    @Override
                    public void onError(Throwable t) {
                    }

                    @Override
                    public void onCompleted() {
                    }
                }));
            }
        }
    }

    private void broadcastEchoAnnouncementGeneral(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException {
        var curr = echoesSent.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : servers) {
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateEchoAnnouncement(request, privateKey, serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> stub.echoAnnouncementGeneral(echo, new StreamObserver<>() {
                    @Override
                    public void onNext(MacReply value) {
                    }

                    @Override
                    public void onError(Throwable t) {
                    }

                    @Override
                    public void onCompleted() {
                    }
                }));
            }
        }
    }


    private void broadcastReadyRegister(Contract.RegisterRequest request) throws GeneralSecurityException {
        var curr = readiesSent.putIfAbsent(request.getMac().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting
            var ready = ContractGenerator.generateReadyRegister(request, privateKey, serverId);
            //If we don't do this we get an error because we can't send RPCs from an RPC
            Context ctx = Context.current().fork();
            ctx.run(() -> {
                for (var stub : servers) {
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
        var curr = readiesSent.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : servers) {
                //Server always send the message ciphered with the receiver's public key
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateReadyAnnouncement(request, privateKey, serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> stub.readyAnnouncement(echo, new StreamObserver<>() {
                    @Override
                    public void onNext(MacReply value) {
                    }

                    @Override
                    public void onError(Throwable t) {
                    }

                    @Override
                    public void onCompleted() {
                    }
                }));
            }
        }
    }

    private void broadcastReadyAnnouncementGeneral(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException {
        var curr = readiesSent.putIfAbsent(request.getSignature().toStringUtf8(), true);
        if (curr == null) {
            //First time broadcasting

            for (var stub : servers) {
                //Server always send the message ciphered with the receiver's public key
                var message = CipherUtils.cipherAndEncode(announcement.getMessage().getBytes(), stub.getServerKey());
                request = request.toBuilder().setMessage(message).build();
                var echo = ContractGenerator.generateReadyAnnouncement(request, privateKey, serverId);
                //If we don't do this we get an error because we can't send RPCs from an RPC
                Context ctx = Context.current().fork();
                ctx.run(() -> stub.readyAnnouncementGeneral(echo, new StreamObserver<>() {
                    @Override
                    public void onNext(MacReply value) {
                    }

                    @Override
                    public void onError(Throwable t) {
                    }

                    @Override
                    public void onCompleted() {
                    }
                }));
            }
        }
    }

    private void deliverRegister(Contract.RegisterRequest request) throws GeneralSecurityException, CommonDomainException, IOException {
        PublicKey pubKey = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        User user = new User(pubKey);
        var curr = users.putIfAbsent(pubKey, user);
        if (curr == null) {
            save(user.toJson());
        }
        deliveredMessages.putIfAbsent(request.getMac().toStringUtf8(), new CountDownLatch(1));
        deliveredMessages.get(request.getMac().toStringUtf8()).countDown();
    }

    private void deliverAnnouncement(Contract.Announcement request) throws CommonDomainException, GeneralSecurityException, IOException {
        //Is called only one time
        var announcement = generateAnnouncement(request, privateKey);
        Set<Contract.ReadyAnnouncement> proofs;
        synchronized (proofs = announcementProofs.get(request.getSignature().toStringUtf8())) {
            proofs.forEach(proof -> announcement.addProof(proof.getServerKey(), Base64.getEncoder().encodeToString(proof.getMac().toByteArray())));
        }
        announcements.putIfAbsent(request.getIdentifier(), announcement);
        save(announcement.toJson(POST_OP_TYPE));
        announcement.getUser().getUserBoard().post(announcement);
        deliveredMessages.computeIfAbsent(request.getIdentifier(), key -> new CountDownLatch(1)).countDown();

    }

    private void deliverAnnouncementGeneral(Contract.Announcement request) throws GeneralSecurityException, CommonDomainException, IOException {
        //Is called only one time
        var announcement = generateAnnouncement(request, generalBoard, privateKey);
        Set<Contract.ReadyAnnouncement> proofs;
        synchronized (proofs = announcementProofs.get(request.getSignature().toStringUtf8())) {
            proofs.forEach(proof -> announcement.addProof(proof.getServerKey(), Base64.getEncoder().encodeToString(proof.getMac().toByteArray())));
        }
        announcements.putIfAbsent(request.getIdentifier(), announcement);
        save(announcement.toJson(POST_GENERAL_OP_TYPE));
        generalBoard.post(announcement);
        deliveredMessages.computeIfAbsent(request.getIdentifier(), key -> new CountDownLatch(1)).countDown();
    }

    private void brbRegister(Contract.RegisterRequest request) throws GeneralSecurityException, InterruptedException {
        broadcastEchoRegister(request); //Received Message start RBR Echo
        deliveredMessages.computeIfAbsent(request.getMac().toStringUtf8(), key -> new CountDownLatch(1)).await();
        deliveredMessages.get(request.getMac().toStringUtf8()).await();
    }

    private void brbAnnouncement(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException, InterruptedException {
        var curr = deliveredMessages.putIfAbsent(request.getIdentifier(), new CountDownLatch(1));
        if (curr == null) {
            broadcastEchoAnnouncement(request, announcement); //Received Message start RBR Echo
        }
        deliveredMessages.get(request.getIdentifier()).await();

    }

    private void brbAnnouncementGeneral(Contract.Announcement request, Announcement announcement) throws GeneralSecurityException, InterruptedException {
        var curr = deliveredMessages.putIfAbsent(request.getIdentifier(), new CountDownLatch(1));
        if (curr == null) {
            broadcastEchoAnnouncementGeneral(request, announcement); //Received Message start RBR Echo
        }
        deliveredMessages.get(request.getIdentifier()).await();
    }


    protected Announcement generateAnnouncement(Contract.Announcement request, AnnouncementBoard board, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
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

        return new Announcement(signature, users.get(key), message, getReferences(request.getReferencesList()), board, request.getSeq());
    }

    protected Announcement generateAnnouncement(Contract.Announcement request, PrivateKey privKey) throws GeneralSecurityException, CommonDomainException {
        PublicKey key = KeyFactory.getInstance(ASYMMETRIC_KEY_ALGORITHM).generatePublic(new X509EncodedKeySpec(request.getPublicKey().toByteArray()));
        byte[] signature = request.getSignature().toByteArray();
        String message = new String(CipherUtils.decodeAndDecipher(request.getMessage(), privKey));

        User user = users.get(key);
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


    private Set<Announcement> getReferences(List<String> referenceIDs) throws InvalidReferenceException {
        // add all references to lists of references
        var references = new HashSet<Announcement>();
        for (var reference : referenceIDs) {
            var announcement = this.announcements.get(reference);
            if (announcement == null) {
                throw new InvalidReferenceException("Invalid Reference: reference provided does not exist");
            }
            if (!references.add(announcement)) {
                //Repeated reference
                throw new InvalidReferenceException("Invalid Reference: Reference is repeated");
            }
        }
        return references;
    }

    //For the persistence manager
    public void addUser(PublicKey key) throws NullUserException, NullPublicKeyException {
        User user = new User(key);
        users.put(key, user);
    }

    public void addAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references, int seq, Map<String, String> broadcastProof)
            throws CommonDomainException {

        var refs = getReferences(references);
        var user = users.get(key);
        var board = user.getUserBoard();

        var announcement = new Announcement(signature, user, message, refs, board, seq, broadcastProof);
        board.post(announcement);
        announcements.put(announcement.getIdentifier(), announcement);
    }

    public void addGeneralAnnouncement(String message, PublicKey key, byte[] signature, ArrayList<String> references, int seq, Map<String, String> broadcastProof)
            throws CommonDomainException {

        var refs = getReferences(references);
        var user = users.get(key);

        var announcement = new Announcement(signature, user, message, refs, generalBoard, seq, broadcastProof);
        generalBoard.post(announcement);
        announcements.put(announcement.getIdentifier(), announcement);
    }


    //Don't want to save when testing
    private void save(JsonObject object) throws IOException {
        if (manager != null) {
            manager.save(object);
        }
    }

    public void addNonce(String nonce) {
        nonces.add(nonce);
    }

    public boolean isReadRepeated(String nonce) {
        return nonces.contains(nonce);
    }

    private static JsonObject readObject(String nonce) {
        var jsonBuilder = Json.createObjectBuilder();
        jsonBuilder.add(JsonConstants.OPERATION_TYPE_KEY, READ_JSON_KEY);
        jsonBuilder.add(NONCE_KEY, nonce);
        return jsonBuilder.build();
    }

    public ConcurrentHashMap<PublicKey, User> getUsers() {
        return users;
    }
}