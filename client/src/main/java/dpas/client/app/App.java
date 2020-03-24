package dpas.client.app;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import com.google.protobuf.ByteString;
import dpas.client.library.Library;
import dpas.common.domain.Announcement;
import dpas.common.domain.exception.CommonDomainException;
import dpas.common.domain.exception.InvalidSignatureException;
import dpas.grpc.contract.Contract;

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


	public void parseAllPostLine (String line, Library lib) {
		try {
			String [] split = line.split(" ");
			if (split.length < 3) {
				System.out.println("Invalid argument: Must be post post/postGeneral <KeyStorePath> <message> <numReferences <references...>");
				return;
			}
			String jksPath = split[1];

			if (!jksPath.endsWith(".jks")) {
				System.out.println("Invalid argument: Client key store must be a JKS file!");
				System.exit(-1);
			}

			File jksFile = new File(jksPath);
			if (!jksFile.exists() || jksFile.isDirectory()) {
				System.out.println("Invalid Argument: Client Key Store File must exist and must not be a directory!");
				System.exit(-1);
			}

			String message = split[2];
			String identifier = UUID.randomUUID().toString();

			char[] jksPassword = System.console().readPassword("Insert JSK Password: ");
			String keyPairAlias = System.console().readLine("Insert Certificate alias: ");

			char[] privKeyPassword = System.console().readPassword("Insert Private Key Password: ");
			KeyStore ks = KeyStore.getInstance("JKS");

			PublicKey pubKey = null;
			PrivateKey priKey = null;

			try (FileInputStream fis = new FileInputStream(jksFile)) {
				ks.load(fis, jksPassword);
				pubKey = ks.getCertificate(keyPairAlias).getPublicKey();
				priKey = (PrivateKey) ks.getKey(keyPairAlias, privKeyPassword);
			}

			int numberOfReferences = Integer.parseInt(split[3]);

			Contract.Announcement[] refs = new Contract.Announcement[numberOfReferences];
			for (int i = 3, j = 0; i < 3 + numberOfReferences; i++, j++) {
				refs[j] = Contract.Announcement.newBuilder()
						.setIdentifier(split[i])
						.build();
			}

			if (split[0].equals("post"))
				lib.post(pubKey, message.toCharArray(), refs, identifier, priKey);
			else
				lib.postGeneral(pubKey, message.toCharArray(), refs, identifier, priKey);

		} catch (KeyStoreException e) {
			System.out.println("Invalid Argument: Could not load JKS keystore");
		} catch (FileNotFoundException e) {
			//Should never happen
			System.out.println("Invalid Argument: File provided does not exist");
		} catch (IOException e) {
			System.out.println("Error: Could not retrieve keys from KeyStore (Did you input the correct passwords and aliases?)!");
		} catch (CertificateException e) {
			System.out.println("Invalid Argument: Could not get certificate with that alias");
		} catch (UnrecoverableKeyException e) {
			System.out.println("Error: Probably mistake in key alias");
		} catch (NoSuchAlgorithmException e) {
			//Should never happen
			System.out.println("Error: JKS does not exist");
		}
	}



}
