package STGC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Objects;
import java.util.Properties;

import java.net.*;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.MessageDigest;


public class STGCMulticastSockets extends MulticastSocket{
	
	private Cipher cipher;
	private SecretKey key;
	private IvParameterSpec ivSpec;
	Key macKey;
	Mac mac;


	public STGCMulticastSockets(int port) throws IOException {
		
		super(port);
		try {
			KeyStore keyStore = KeyStore.getInstance("JCEKS");
			// Keystore where symmetric keys are stored (type JCEKS)
			FileInputStream stream = new FileInputStream("mykeystore.jceks");
			// carregar keystore
			keyStore.load(stream, "projeto".toCharArray());

			PasswordProtection keyPassword = new PasswordProtection("srsc1718".toCharArray());
			PasswordProtection keyPassword2 = new PasswordProtection("srsc1718?yes!".toCharArray());
			//ler chave para cipher
			KeyStore.Entry entry = keyStore.getEntry("mykey1", keyPassword);
			key = ((KeyStore.SecretKeyEntry) entry).getSecretKey();
			//ler chave para mac
			KeyStore.Entry entry2 = keyStore.getEntry("mykey3", keyPassword2);
			macKey = ((KeyStore.SecretKeyEntry) entry2).getSecretKey();

			//ler o ficheiro de configurações
			readConfig();
		}catch(Exception e) {

		}

	}
	public void send(DatagramPacket packet) {
		
		byte[] cipherdata = null;

		try {
			cipherdata = this.encrypt(packet.getData());
		} catch (Exception e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		packet.setData(cipherdata);
		try {
			super.send(packet);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		//System.out.println(Utils.toHex(cipherPacket.getData()));
	}

	public void receive(DatagramPacket packet) throws IOException {
		
		int size = packet.getLength();
		super.receive(packet);
		byte[] buffer = new byte[size];
		byte[] receivedcipher = new byte[packet.getLength()];
		System.arraycopy(packet.getData(), packet.getOffset(), receivedcipher, 0, packet.getLength());

		byte[] messagedata = null;
		try {
			messagedata = this.desencrypt(receivedcipher,packet.getLength());
		} catch (Exception e) {

			e.printStackTrace();
		}
		System.arraycopy(messagedata, 0, buffer, 0, messagedata.length);

		packet.setData(buffer);

	}
	public byte[] encrypt(byte[] message) throws Exception {

		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

		byte[] cipherText = new byte[cipher.getOutputSize(message.length + mac.getMacLength())];

		int ctLength = cipher.update(message, 0, message.length, cipherText, 0);

		// Parte do MAC

		mac.init(macKey);
		mac.update(message);

		ctLength += cipher.doFinal(mac.doFinal(), 0, mac.getMacLength(), cipherText, ctLength);

		byte[] headerAndPayload = createHeaderAndAddMessage(cipherText);
		return headerAndPayload;

	}
	public byte[] desencrypt(byte[] message,int lenght) throws Exception {
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		message = ReadMessage(message);
		byte[] plainText = cipher.doFinal(message);
		int messageLength = plainText.length - mac.getMacLength();

		// Verificaao Mac

		mac.init(macKey);
		mac.update(plainText, 0, messageLength);

		byte[] messageHash = new byte[mac.getMacLength()];
		System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);

		byte[] messagePlain =new byte[lenght];
		System.arraycopy(plainText, 0, messagePlain, 0, messageLength);

		if(!MessageDigest.isEqual(mac.doFinal(), messageHash)){
			System.exit(1);
		}
		
		return messagePlain;
	}

	private void readConfig() throws Exception {
		
		String macProvider=null;
		String cipherProvider=null;
		String cipherConfig=null;
		String macCipher=null;
		Properties prop = new Properties();
		// the configuration file name
		String fileName = "ciphersuite.conf";
		ClassLoader classLoader = STGCMulticastSockets.class.getClassLoader();

		// Make sure that the configuration file exists
		URL res = Objects.requireNonNull(classLoader.getResource(fileName),
				"Can't find configuration file ciphersuite.conf");

		InputStream is = new FileInputStream(res.getFile());

		// load the properties file
		prop.load(is);

		macProvider = prop.getProperty("macProvider");
		macCipher = prop.getProperty("macCipher");
		cipherProvider = prop.getProperty("cipherProvider");
		cipherConfig = prop.getProperty("cipherConfig");

		//nao sei o que fazer com isto
		byte[] ivBytes = new byte[] {
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
				0x08, 0x09, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15 
		};

		ivSpec = new IvParameterSpec(ivBytes);
		mac = Mac.getInstance(macCipher, macProvider);
		cipher = Cipher.getInstance(cipherConfig, cipherProvider);
	}
	private byte[] createHeaderAndAddMessage(byte[] payload) throws Exception {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);

		byte[] version = new byte[] {0x11};
		byte[] space = new byte[] {0x00};
		byte[] type = new byte[] {0x01};// 0x01 para app 0x02 para o que seja
		dataStream.write(version);
		dataStream.write(space);
		dataStream.write(type);
		dataStream.write(space);
		dataStream.writeShort(payload.length);
		dataStream.write(payload);
		dataStream.close();

		byte[] data = byteStream.toByteArray();
		
		return data;
	}
	private byte[] ReadMessage(byte[] messagedata) throws Exception {
		
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(messagedata));
		byte version = istream.readByte();
		istream.readByte();
		byte type = istream.readByte();
		istream.readByte();
		int size = istream.readShort();
		byte[] data = new byte[size];
		istream.readFully(data);
		
		return data;
	}

}
