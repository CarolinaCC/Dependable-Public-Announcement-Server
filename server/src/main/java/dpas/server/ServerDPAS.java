package dpas.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import dpas.server.persistence.PersistenceManager;
import io.grpc.BindableService;
import io.grpc.Server;
import io.grpc.netty.shaded.io.grpc.netty.NettyServerBuilder;

public class ServerDPAS {

	public static void main(String[] args) throws Exception {
		System.out.println(ServerDPAS.class.getSimpleName());

		// check arguments
		if (args.length < 5) {
			System.err.println("Argument(s) missing!");
			System.err.printf("<Usage> java port saveFile ServerKeyStoreFile ServerPublicKeyFile ServerKeyStorePassword %s %n",
					ServerDPAS.class.getName());
			return;
		}

		String jksPath = args[2];
		String pubKeyPath = args[3];

		if (!jksPath.endsWith(".jks")) {
			System.out.println("Invalid argument: Client key store must be a JKS file!");
			System.exit(-1);
		}
		if (!pubKeyPath.endsWith(".der")) {
			System.out.println("Invalid Argument: Client Public Key must be in der format!");
			System.exit(-1);
		}

		File jksFile = new File(jksPath);
		if (!jksFile.exists() || jksFile.isDirectory()) {
			System.out.println("Invalid Argument: Client Key Store File must exist and must not be a directory!");
			System.exit(-1);
		}
		File pubKeyFile = new File(pubKeyPath);
		if (!pubKeyFile.exists() || pubKeyFile.isDirectory()) {
			System.out.println("Invalid Argument: Client Public Key File must exist and must not be a directory!");
			System.exit(-1);
		}

		CertificateFactory factory = CertificateFactory.getInstance("X.509");

		System.out.println("Retrieving server public key from certificate...");
		X509Certificate serverKeyCertificate = null;
		try (FileInputStream fis = new FileInputStream(pubKeyFile)) {
			serverKeyCertificate = (X509Certificate) factory.generateCertificate(fis);
		} catch (CertificateException e) {
			System.out.println("Error: Could not retrieve server public key from file provided!");
			System.exit(-1);
		}
		PublicKey pubKey = serverKeyCertificate.getPublicKey();
		if (!pubKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Server public key must be an RSA key");
			System.exit(-1);
		}
		System.out.println("Retrieved server public key successfully!");

		System.out.println("Retrieving server private key from keystore...");
		char[] keyStorePassword = args[4].toCharArray();
		KeyStore ks = KeyStore.getInstance("JKS");
		PrivateKey privKey = null;
		try (FileInputStream fis = new FileInputStream(jksFile)) {
			ks.load(fis, keyStorePassword);
			privKey = (PrivateKey) ks.getKey("server", keyStorePassword);
		} catch (IOException e) {
			System.out.println("Error: Could not server client key from KeyStore! (Is the password correct?)");
			System.exit(-1);
		}
		if (!privKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Client server key must be an RSA key");
			System.exit(-1);
		}
		System.out.println("Retrieved server private key successfully!");

		Server server = startServer(Integer.parseInt(args[0]), args[1]);

		// Do not exit the main thread. Wait until server is terminated.
		server.awaitTermination();
	}

	public static Server startServer(int port, String saveFile) {
		try {
			final BindableService impl = new PersistenceManager(saveFile).load();
			final Server server = NettyServerBuilder.forPort(port).addService(impl).build();

			server.start();
			return server;
		} catch (Exception e) {
			System.out.println("Error Initializing server: Invalid State Load");
			System.exit(1);
		}
		// Code never reaches here
		return null;
	}
}
