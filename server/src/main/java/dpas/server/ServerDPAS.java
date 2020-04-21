package dpas.server;

import dpas.grpc.contract.ServiceDPASGrpc;
import dpas.server.persistence.PersistenceManager;
import dpas.server.security.SecurityManager;
import dpas.utils.link.PerfectStub;
import io.grpc.BindableService;
import io.grpc.ManagedChannel;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;
import io.grpc.netty.shaded.io.netty.channel.nio.NioEventLoopGroup;
import io.grpc.netty.shaded.io.netty.channel.socket.nio.NioSocketChannel;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.concurrent.Executors;

public class ServerDPAS {

    public static void main(String[] args) throws Exception {
        System.out.println(ServerDPAS.class.getSimpleName());

        // check arguments
        if (args.length < 7) {
            System.err.println("Argument(s) missing!");
            System.err.printf("<Usage> java port SaveFile KeyStoreFile KeyStorePassword ServerKeyPairAlias ServerPrivateKeyPassword maxFaults %s %n",
                    ServerDPAS.class.getName());
            return;
        }

        String jksPath = args[2];
        String jksPassword = args[3];
        String keyPairAlias = args[4];
        String privKeyPassword = args[5];
        int numFaults = Integer.parseInt(args[6]);

        if (!jksPath.endsWith(".jks")) {
            System.out.println("Invalid argument: Client key store must be a JKS file!");
            System.exit(-1);
        }

        File jksFile = new File(jksPath);
        if (!jksFile.exists() || jksFile.isDirectory()) {
            System.out.println("Invalid Argument: Client Key Store File must exist and must not be a directory!");
            System.exit(-1);
        }

        System.out.println("Retrieving server key pair from keystore...");
        KeyStore ks = KeyStore.getInstance("JKS");
        PrivateKey privKey = null;
        PublicKey pubKey = null;
        try (FileInputStream fis = new FileInputStream(jksFile)) {
            ks.load(fis, jksPassword.toCharArray());
            privKey = (PrivateKey) ks.getKey(keyPairAlias, privKeyPassword.toCharArray());
            pubKey = ks.getCertificate(keyPairAlias).getPublicKey();
        } catch (IOException e) {
            System.out.println("Error: Could not get server key pair from KeyStore! (Are the password and alias correct?)");
            System.exit(-1);
        }
        if (!privKey.getAlgorithm().equals("RSA")) {
            System.out.println("Error: Server private key must be an RSA key");
            System.exit(-1);
        }
        if (!pubKey.getAlgorithm().equals("RSA")) {
            System.out.println("Error: Server public key must be an RSA key");
            System.exit(-1);
        }

        System.out.println("Retrieved server key pair successfully!");

        var stubs = loadServerKeys("localhost", numFaults, ks);

        Server server = startServer(Integer.parseInt(args[0]), args[1], privKey, pubKey, stubs, numFaults);

        // Do not exit the main thread. Wait until server is terminated.
        server.awaitTermination();
    }

    public static Server startServer(int port, String saveFile, PrivateKey privateKey, PublicKey pubKey, List<PerfectStub> stubs, int numFaults) {
        try {
            final BindableService impl = new PersistenceManager(saveFile).load(new SecurityManager(), privateKey,
                    stubs, Base64.getEncoder().encodeToString(pubKey.getEncoded()), numFaults);
            final Server server = NettyServerBuilder.forPort(port).addService(impl).build();
            server.start();
            return server;
        } catch (Exception e) {
            System.out.println("Error Initializing server: " + e.getMessage());
            System.exit(1);
        }
        // Code never reaches here
        return null;
    }

    public static List<PerfectStub> loadServerKeys(String host, int maxFaults, KeyStore ks) throws KeyStoreException {
        var stubs = new ArrayList<PerfectStub>();
        int numServers = 3 * maxFaults + 1;
        for(int i = 1; i <= numServers; ++i) {
            var alias = "server-" + i;
            var pubKey = ks.getCertificate(alias).getPublicKey();
            int port = 9000 + i;
            var executor = Executors.newSingleThreadExecutor(); //One thread for each stub
            var eventGroup = new NioEventLoopGroup(1); //One thread for each channel
            ManagedChannel channel = NettyChannelBuilder
                    .forAddress(host, port)
                    .usePlaintext()
                    .channelType(NioSocketChannel.class)
                    .eventLoopGroup(eventGroup)
                    .executor(executor)
                    .build();
            var stub = new PerfectStub(ServiceDPASGrpc.newStub(channel), pubKey);
            stubs.add(stub);
        }
        return stubs;
    }
}
