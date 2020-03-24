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

		if (args.length < 2) {
			System.out.println("Argument(s) missing!");
			System.out.printf("<Usage> java ServerAddress ServerPort KeyStoreFile %s %n", App.class.getName());
			System.exit(-1);
		}
		String serverAddr = args[0];
		int port = Integer.parseInt(args[1]);
		
		Library lib = new Library(serverAddr, port);
		while(true) {
			String line = System.console().readLine("Enter Command: ");
			String[] split = line.split(" ");
			if(split.length == 0) {
				continue;
			}
			switch(split[0]) {
				case "register":
					parseRegisterLine(line, lib);
					break;
				case "read":
					break;
				case "readGeneral":
					break;
				case "post":
					break;
				case "postGeneral":
					break;
				default:
					break;
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
			System.out.println("Error: An Error Occurred while reading the keystore");			
		} catch (NoSuchAlgorithmException e) {
			//Should never happen
			System.out.println("Error: JKS does not exist");	
			
		}
	}
}
