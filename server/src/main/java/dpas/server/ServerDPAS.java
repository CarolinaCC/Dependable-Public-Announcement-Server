package dpas.server;

import dpas.server.persistence.PersistenceManager;
import dpas.server.security.SecurityManager;
import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ServerDPAS {

    public static void main(String[] args) throws Exception {
        System.out.println(ServerDPAS.class.getSimpleName());

        // check arguments
        if (args.length < 6) {
            System.err.println("Argument(s) missing!");
            System.err.printf("<Usage> java port SaveFile KeyStoreFile KeyStorePassword ServerKeyPairAlias ServerPrivateKeyPassword %s %n",
                    ServerDPAS.class.getName());
            return;
        }

        String jksPath = args[2];
        String jksPassword = args[3];
        String keyPairAlias = args[4];
        String privKeyPassword = args[5];

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

        Server server = startServer(Integer.parseInt(args[0]), args[1], privKey);

        // Do not exit the main thread. Wait until server is terminated.
        server.awaitTermination();
    }

    public static Server startServer(int port, String saveFile, PrivateKey privateKey) {
        try {
            final BindableService impl = new PersistenceManager(saveFile).load(new SecurityManager(), privateKey);
            final Server server = NettyServerBuilder.forPort(port).addService(impl).build();
            server.start();
            return server;
        } catch (Exception e) {
            System.out.println("Error Initializing server: Invalid State Load " + e.getMessage());
            System.exit(1);
        }
        // Code never reaches here
        return null;
    }
}
