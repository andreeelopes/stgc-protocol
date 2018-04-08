package STGC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
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
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.bouncycastle.util.Arrays;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PasswordProtection;
import java.security.MessageDigest;
import java.security.SecureRandom;


public class STGCMulticastSockets extends MulticastSocket{
	
	private Cipher cipher;
	private SecretKey key;
	private IvParameterSpec ivSpec;
	Key macKey;
	Mac mac;
	private InetAddress group;
	private byte[] version;
	private byte[] type;
	private static final int TIMETOEXPIRE= 10000;
	private MyCache cache;
	public STGCMulticastSockets(int port) throws IOException {
		
		super(port);
		cache=new MyCache();
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

		}catch(Exception e) {

		}

	}
	public void joinGroup(InetAddress mcastaddr)
            throws IOException{
		super.joinGroup(mcastaddr);
		this.group=mcastaddr;
		try {
			this.readConfig();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
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
		if(messagedata==null)
			return;
		System.arraycopy(messagedata, 0, buffer, 0, messagedata.length);

		packet.setData(buffer);

	}
	public byte[] encrypt(byte[] message) throws Exception {

		cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
		int nonceC = new SecureRandom().nextInt();

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);
		dataStream.writeInt(nonceC);
		dataStream.write(message);

		// Parte do MAC

		mac.init(macKey);
		mac.update(Utils.toByteArray(nonceC));
		mac.update(message);
		byte[] machash=mac.doFinal();
		System.out.println(Utils.toHex(machash));
		dataStream.write(machash);
		dataStream.close();
		byte[] Text = byteStream.toByteArray();

		byte[] cipherText=cipher.doFinal(Text);
		//System.out.println(Utils.toHex(plainText));
		byte[] headerAndPayload = createHeaderAndAddMessage(cipherText);
		return headerAndPayload;

	}
	public byte[] desencrypt(byte[] message,int lenght) throws Exception {
		
		cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
		//message = ReadMessage(message);
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(message));
		byte version = istream.readByte();
		if(version!= this.version[0])
			return null;
		istream.readByte();
		byte type = istream.readByte();
		istream.readByte();
		int size = istream.readShort();
		
		byte[] data = new byte[size];
		istream.readFully(data);
		if(type==this.type[0]) {
		byte[] plainText = cipher.doFinal(data);
		istream = new DataInputStream(new ByteArrayInputStream(plainText));
		
		int nonce=istream.readInt();
		if(!cache.isValid(nonce)) {
			return null;
		}
		else {
			cache.add(nonce, TIMETOEXPIRE);
		}
		int messageLength = (plainText.length-4) - mac.getMacLength();
		
		// Verificaao Mac

		mac.init(macKey);
		mac.update(Utils.toByteArray(nonce));
		byte[] messagePlain =new byte[messageLength];
		System.arraycopy(plainText, 4, messagePlain, 0, messageLength);
		mac.update(messagePlain);
	
		

		byte[] messageHash = new byte[mac.getMacLength()];
		System.arraycopy(plainText, messageLength+4, messageHash, 0, messageHash.length);

		byte[] machash= mac.doFinal();

		if(!MessageDigest.isEqual(machash, messageHash)){
			return null;
		}
		return messagePlain;

		}
		else {
			return data;
		}
			}
	private void readConfig() throws Exception {

		String macProvider=null;
		String cipherProvider=null;
		String cipherConfig=null;
		String macCipher=null;
	    try {

		File fXmlFile = new File("ciphersuite.xml");
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(fXmlFile);
		//optional, but recommended
		//read this - http://stackoverflow.com/questions/13786607/normalization-in-dom-parsing-with-java-how-does-it-work
		doc.getDocumentElement().normalize();

		System.out.println("Root element :" + doc.getDocumentElement().getNodeName());
				
		NodeList nList = doc.getElementsByTagName("room");
				
		System.out.println("----------------------------");

		for (int temp = 0; temp < nList.getLength(); temp++) {

			Node nNode = nList.item(temp);
					
			System.out.println("\nCurrent Element :" + nNode.getNodeName());
					
			if (nNode.getNodeType() == Node.ELEMENT_NODE) {

				Element eElement = (Element) nNode;

				String roomIP= eElement.getAttribute("ip");
				System.out.println(roomIP+" "+ group.getHostAddress());
				if(roomIP.equals(group.getHostAddress())) {
					
					macProvider=eElement.getElementsByTagName("macProvider").item(0).getTextContent();
					cipherProvider=eElement.getElementsByTagName("cipherProvider").item(0).getTextContent();
					cipherConfig=eElement.getElementsByTagName("cipherConfig").item(0).getTextContent();
					macCipher=eElement.getElementsByTagName("macCipher").item(0).getTextContent();
				}

			}
		}
	    } catch (Exception e) {
		e.printStackTrace();
	    }
	    byte[] ivBytes= new byte[] {
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

		version = new byte[] {0x11};
		byte[] space = new byte[] {0x00};
		type = new byte[] {0x01};// 0x01 para app 0x02 para o que seja
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
		System.out.println(version!= this.version[0]);
		if(version!= this.version[0])
			return null;
		istream.readByte();
		byte type = istream.readByte();
		istream.readByte();
		int size = istream.readShort();
		byte[] data = new byte[size];
		istream.readFully(data);
		
		return data;
	}

}
