package dpas.client;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import dpas.client.library.Library;

public class Main {
	public static void main(String[] args) throws FileNotFoundException, IOException, KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {

		if (args.length < 5) {
			System.out.println("Argument(s) missing!");
			System.out.printf("<Usage> java ServerAddress ServerPort ClientKeyStoreFile "
					+ "ClientPublicKeyFile ServerPublicKeyFile %s %n", Main.class.getName());
			System.exit(-1);
		}
		String serverAddr = args[0];
		int port = Integer.parseInt(args[1]);
		String jksPath = args[2];
		String pubKeyPath = args[3];
		String serverPubKeyPath = args[4];

		if (!jksPath.endsWith(".jks")) {
			System.out.println("Invalid argument: Client key store must be a JKS file!");
			System.exit(-1);
		}
		if (!pubKeyPath.endsWith(".der")) {
			System.out.println("Invalid Argument: Client Public Key must be in der format!");
			System.exit(-1);
		}
		if (!serverPubKeyPath.endsWith(".der")) {
			System.out.println("Invalid Argument: Server Public Key must be in der format!");
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
		File serverPubKeyFile = new File(serverPubKeyPath);
		if (!serverPubKeyFile.exists() || serverPubKeyFile.isDirectory()) {
			System.out.println("Invalid Argument: Server Public Key File must exist and must not be a directory!");
			System.exit(-1);
		}

		CertificateFactory factory = CertificateFactory.getInstance("X.509");

		System.out.println("Retrieving client public key from certificate...");
		X509Certificate pubKeyCertificate = null;
		try (FileInputStream fis = new FileInputStream(pubKeyFile)) {
			pubKeyCertificate = (X509Certificate) factory.generateCertificate(fis);
		} catch (CertificateException e) {
			System.out.println("Error: Could not retrieve client public key from file provided!");
			System.exit(-1);
		}
		PublicKey pubKey = pubKeyCertificate.getPublicKey();
		if (!pubKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Client public key must be an RSA key");
			System.exit(-1);
		}
		System.out.println("Retrieved client public key successfully!");

		System.out.println("Retrieving server public key from certificate...");
		X509Certificate serverKeyCertificate = null;
		try (FileInputStream fis = new FileInputStream(serverPubKeyFile)) {
			serverKeyCertificate = (X509Certificate) factory.generateCertificate(fis);
		} catch (CertificateException e) {
			System.out.println("Error: Could not retrieve server public key from file provided!");
			System.exit(-1);
		}
		PublicKey serverPubKey = serverKeyCertificate.getPublicKey();
		if (!serverPubKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Server public key must be an RSA key");
			System.exit(-1);
		}
		System.out.println("Retrieved server public key successfully!");

		System.out.println("Retrieving client private key from keystore...");
		char[] keyStorePassword = System.console().readPassword("Enter Key Store Password: ");
		KeyStore ks = KeyStore.getInstance("JKS");
		PrivateKey privKey = null;
		try (FileInputStream fis = new FileInputStream(jksFile)) {
			ks.load(fis, keyStorePassword);
			privKey = (PrivateKey) ks.getKey("client", keyStorePassword);
		} catch (IOException e) {
			System.out.println(
					"Error: Could not retrieve client key from KeyStore (Did you input the correct password?)!");
			System.exit(-1);
		}
		if (!privKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Client private key must be an RSA key");
			System.exit(-1);
		}
		System.out.println("Retrieved client private key successfully!");

		Library lib = new Library(serverAddr, port);
	}
}
