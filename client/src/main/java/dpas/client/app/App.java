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
import java.util.Base64;
import java.util.UUID;

import dpas.client.library.Library;
import dpas.grpc.contract.Contract;
import dpas.grpc.contract.Contract.Announcement;

public class App {

	public static void main(String[] args) {

		if (args.length < 2) {
			System.out.println("Argument(s) missing!");
			System.out.printf("<Usage> java ServerAddress ServerPort %s %n", App.class.getName());
			System.exit(-1);
		}
		String serverAddr = args[0];
		int port = Integer.parseInt(args[1]);
		
		Library lib = new Library(serverAddr, port);
		printHelp();
		while(true) {
			String line = System.console().readLine("Enter Command: ");
			String[] split = line.split(" ");
			if(split.length == 0) {
				printHelp();
				continue;
			}
			switch(split[0]) {
				case "register":
					parseRegisterLine(line, lib);
					printHelp();
					break;
				case "read":
					parseReadLine(line, lib);
					printHelp();
					break;
				case "readGeneral":
					parseReadGeneralLine(line, lib);
					printHelp();
					break;
				case "post":
				case "postGeneral":
					parsePostLine(line, lib);
					printHelp();
					break;
				case "quit":
					return;
				default:
					printHelp();
			}
		}
	}
	
	
	public static void parseRegisterLine(String line, Library lib) {
		try {
			String[] split = line.split(" ");
			if (split.length != 2) {
				System.out.println("Invalid argument: Must be register <KeystorePath>");
				return;
			}
		
			String jksPath = split[1];
	
			if (!jksPath.endsWith(".jks")) {
				System.out.println("Invalid argument: Client key store must be a JKS file!");
				return;
			}
			File jksFile = new File(jksPath);
			if (!jksFile.exists() || jksFile.isDirectory()) {
				System.out.println("Invalid Argument: Client Key Store File must exist and must not be a directory!");
				return;
			}
		
			char[] jksPassword = System.console().readPassword("Insert JKS Password: ");
			String alias = System.console().readLine("Insert Certificate Alias: ");
			KeyStore ks = KeyStore.getInstance("JKS");
			
			PublicKey pubKey = null;
			try (FileInputStream fis = new FileInputStream(jksFile)) {
				ks.load(fis, jksPassword);
				pubKey = ks.getCertificate(alias).getPublicKey();
			}
			if (!pubKey.getAlgorithm().equals("RSA")) {
				System.out.println("Error: Client key must be an RSA key");
				return;
			}
			
			lib.register(pubKey);
		} catch (KeyStoreException e) {
			System.out.println("Invalid Argument: Could not load JKS keystore");
		} catch (CertificateException e) {
			System.out.println("Invalid Argument: Could not get certificate with that alias");
		} catch(FileNotFoundException e) {
			//Should never happen
			System.out.println("Invalid Argument: File provided does not exist");
		} catch (IOException e) {
			System.out.println("Error: Could not retrieve keys from KeyStore (Did you input the correct passwords and aliases?)!");			
		} catch (NoSuchAlgorithmException e) {
			//Should never happen
			System.out.println("Error: JKS does not exist");		
		} catch (NullPointerException e) {
			System.out.println("Invalid Argument: Key with that alias does not exist");
		}
	}

	public static void parseReadLine(String read, Library lib) {
		try {
			String[] readSplit = read.split(" ");
			if (readSplit.length != 3) {
				System.out.println("Invalid argument: Must be read <KeystorePath> <number>");
				return;
			}
			int number = Integer.parseInt(readSplit[2]);
			String jksPath = readSplit[1];

			if (!jksPath.endsWith(".jks")) {
				System.out.println("Invalid argument: Client key store must be a JKS file!");
				System.exit(-1);
			}

			File jksFile = new File(jksPath);
			if (!jksFile.exists() || jksFile.isDirectory()) {
				System.out.println("Invalid Argument: Client Key Store File must exist and must not be a directory!");
				System.exit(-1);
			}
			char[] jksPassword = System.console().readPassword("Insert JKS Password: ");
			String alias = System.console().readLine("Insert Certificate Alias: ");
			KeyStore ks = KeyStore.getInstance("JKS");
			
			PublicKey pubKey;
			
			try (FileInputStream fis = new FileInputStream(jksFile)) {
				ks.load(fis, jksPassword);
				pubKey = ks.getCertificate(alias).getPublicKey();	
			}
			Announcement[] a = lib.read(pubKey, number);
			printAnnouncements(a);
		}
		catch (IOException e) {
			System.out.println("Error: Could not retrieve keys from KeyStore (Did you input the correct passwords and aliases?)!");
		} catch (KeyStoreException e) {
			System.out.println("Error: Could not retrieve keys from KeyStore (Did you input the correct passwords and aliases?)!");
		} catch (CertificateException e) {
			System.out.println("Error: Could not load key store (Wrong password)!");
		} catch (NoSuchAlgorithmException e) {
			System.out.println("Error: Could not retrieve keys from KeyStore (Did you input the correct passwords and aliases?)!");
		}
	}
	
	public static void parseReadGeneralLine(String readGeneral, Library lib) {

		String[] readSplit = readGeneral.split(" ");
		if (readSplit.length != 2) {
			System.out.println("Invalid argument: Must be readGeneral <number>");
		}
		int number = Integer.parseInt(readSplit[1]);
		Announcement[] a = lib.readGeneral(number);
		printAnnouncements(a);
	}
	
	public static void printAnnouncements(Announcement[] announcements) {
		System.out.println();
		for(var announcement: announcements) {
			System.out.println("Identifier:\t" + announcement.getHash());
			System.out.println("Sequencer:\t" + announcement.getSequencer());
			System.out.println("Message:\t" + announcement.getMessage());
			System.out.print("References:");
			for(var ref: announcement.getReferencesList()) {
				System.out.print("\t" + ref);
			}
			System.out.println();
			System.out.println("Signature:\t"+ Base64.getEncoder().encodeToString(announcement.getSignature().toByteArray()));
			System.out.println("Author:\t" + Base64.getEncoder().encodeToString(announcement.getPublicKey().toByteArray()));
			System.out.println();
		}
	}
	
	public static void printHelp() {
		System.out.println();
		System.out.println("Avaliable commands:");
		System.out.println("\tregister <KeyStorePath>");
		System.out.println("\tpost <KeyStorePath> <message> <numReferences> <references...>");
		System.out.println("\tpostGeneral <KeyStorePath> <message> <numReferences> <references...>");
		System.out.println("\tread <KeyStorePath> <number>");
		System.out.println("\treadGeneral <number>");
		System.out.println("\tquit");
		System.out.println();
	}


	public static void parsePostLine (String line, Library lib) {
		try {
			String [] split = line.split(" ");
			if (split.length < 3) {
				System.out.println("Invalid argument: Must be post/postGeneral <KeyStorePath> <message> <numReferences <references...>");
				return;
			}
			
			if (split.length != 4 + Integer.parseInt(split[3])) {
				System.out.println("Invalid Argument: Number of references provided does not match real value");
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

			char[] jksPassword = System.console().readPassword("Insert JKS Password: ");
			String keyPairAlias = System.console().readLine("Insert Certificate Alias: ");

			char[] privKeyPassword = System.console().readPassword("Insert PrivateKey Password: ");
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
			for (int i = 4, j = 0; i < 4 + numberOfReferences; i++, j++) {
				refs[j] = Contract.Announcement.newBuilder()
						.setHash(split[i])
						.build();
			}

			if (split[0].equals("post"))
				lib.post(pubKey, message.toCharArray(), refs, priKey);
			else
				lib.postGeneral(pubKey, message.toCharArray(), refs, priKey);

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
