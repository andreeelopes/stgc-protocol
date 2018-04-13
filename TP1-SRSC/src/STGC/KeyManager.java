package STGC;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class KeyManager {


	private final static String keyStoreFile = "mykeystore.jceks";//path to key store
	private static KeyStore keyStore;
	private static String keyStorePwd;
	private static String keyMasterPwd; //the 'master' password for all key entries (just to ease development)


	public static void setCredencials(String keyStorePwd, String keyMasterPassword) {

		KeyManager.keyStore = createKeyStore(keyStoreFile, keyStorePwd);
		KeyManager.keyStorePwd = keyStorePwd;
		keyMasterPwd = keyMasterPassword;
	}

	private static KeyStore createKeyStore(String fileName, String pw){
		File file = new File(fileName);
		KeyStore keyStore = null;

		try {
			keyStore = KeyStore.getInstance("JCEKS");

			if (file.exists()) {// .keystore file already exists => load it
				try {
					keyStore.load(new FileInputStream(file), pw.toCharArray());
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else {// .keystore file not created yet => create it
				keyStore.load(null, null);
				try {
					keyStore.store(new FileOutputStream(fileName), pw.toCharArray());
				} catch (Exception e) {
					e.printStackTrace();
				}
			}

		} catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
			e.printStackTrace();
		}

		return keyStore;
	}


	public static SecretKey generateKey(String algorithm, String provider, int keySize) {
		SecretKey secretKey = null;
		KeyGenerator keyGen = null;
		try {
			keyGen = KeyGenerator.getInstance(algorithm, provider);
			keyGen.init(keySize);
			secretKey = keyGen.generateKey();
			
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			e.printStackTrace();
		}

		return secretKey;
	}

	public static void storeKey(SecretKey key, String entryName) {

		KeyStore.SecretKeyEntry keyStoreEntry = new KeyStore.SecretKeyEntry(key);
		PasswordProtection keyPassword = new PasswordProtection(keyMasterPwd.toCharArray());
		try {
			keyStore.setEntry(entryName, keyStoreEntry, keyPassword);
			keyStore.store(new FileOutputStream(keyStoreFile), keyStorePwd.toCharArray());
		} catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException e) {
			e.printStackTrace();
		}
	}

	/**
	 * 
	 * @param keyName
	 * @return returns null if key entry doesn't exists
	 */
	public static Key getKey(String keyName){ 

		PasswordProtection pwdProtection = new PasswordProtection(keyMasterPwd.toCharArray());
		KeyStore.Entry entry = null;
		Key key = null;
		try {
			entry = keyStore.getEntry(keyName, pwdProtection);
		} catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
			e.printStackTrace();
		}
		
		if(entry != null)
			key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();

		return key;
	}


}
