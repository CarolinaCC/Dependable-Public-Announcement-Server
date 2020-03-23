package dpas.client.app;

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

import dpas.client.library.Library;		

public class App {
	public static void main(String[] args) throws FileNotFoundException, IOException, KeyStoreException,
			NoSuchAlgorithmException, UnrecoverableKeyException, CertificateException {

		if (args.length < 7) {
			System.out.println("Argument(s) missing!");
			System.out.printf("<Usage> java ServerAddress ServerPort KeyStoreFile "
					+ "KeyStorePassword ClientKeyPairAlias PrivateKeyPassword ServerPublicKeyAlias %s %n", App.class.getName());
			System.exit(-1);
		}
		String serverAddr = args[0];
		int port = Integer.parseInt(args[1]);
		String jksPath = args[2];
		String jksPassword = args[3];
		String keyPairAlias = args[4];
		String privKeyPassword = args[5];
		String serverCertAlias = args[6];

		if (!jksPath.endsWith(".jks")) {
			System.out.println("Invalid argument: Client key store must be a JKS file!");
			System.exit(-1);
		}

		File jksFile = new File(jksPath);
		if (!jksFile.exists() || jksFile.isDirectory()) {
			System.out.println("Invalid Argument: Client Key Store File must exist and must not be a directory!");
			System.exit(-1);
		}
		
		System.out.println("Retrieving Keys from keystore...");
		KeyStore ks = KeyStore.getInstance("JKS");
		PrivateKey privKey = null;
		PublicKey pubKey = null;
		PublicKey serverPubKey = null;
		try (FileInputStream fis = new FileInputStream(jksFile)) {
			ks.load(fis, jksPassword.toCharArray());
			privKey = (PrivateKey) ks.getKey(keyPairAlias, privKeyPassword.toCharArray());
			pubKey = ks.getCertificate(keyPairAlias).getPublicKey();
			serverPubKey = ks.getCertificate(serverCertAlias).getPublicKey();
		} catch (IOException | UnrecoverableKeyException e) {
			System.out.println(
					"Error: Could not retrieve keys from KeyStore (Did you input the correct passwords and aliases?)!");
			System.exit(-1);
		}
		if (!privKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Client private key must be an RSA key");
			System.exit(-1);
		}
		if (!pubKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Client public key must be an RSA key");
			System.exit(-1);
		}
		if (!serverPubKey.getAlgorithm().equals("RSA")) {
			System.out.println("Error: Server public key must be an RSA key");
			System.exit(-1);
		}
		System.out.println("Retrieved keys from keystore successfully!");

		Library lib = new Library(serverAddr, port);
	}
}
