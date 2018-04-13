package STGC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.KeyStore.PasswordProtection;
import java.util.Arrays;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AuthenticationServer {


	private static MulticastSocket socket;
	private static InetAddress ipmcAS;
	private static int portAS;
	private static Key pbeKey;
	private static String ipmcRequested; //the requested app multicast ip by the client
	private static byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae };
	private static int iterationCount = 2048;
	private static Mac mac_AS;
	private static SecretKeySpec macKey_AS;
	private static int nOnceHeader;
	private static String pwdKeyStore;
	private static String pwdKey;
	private static MyCache cache;
	private static String cipherSuitePBE;
	private static String macAlgorithmPBE;
	private static String macProviderPBE;
	private static String cipherProviderPBE;
	private static String macKHashAlgorithm;

	private static KeyManager keyMan; //creates new keystores and entries

	private static Map<String, byte[]> mcIVs = new HashMap<String, byte[]>(); //a map that holds the inicializations vectors for each multicast
	

	private static final int TIMETOEXPIRE= 10000;

	public static void main(String[] args) throws Exception {
		System.err.println("How to execute: AuthenticationServer " 
				+ "<passwordToKeyStore> <passwordToKey>  {<ipmcAS>}  {<port>}");  
		System.err.println("       - port default = 1800");
		System.err.println("       - ipmcAS default = 239.255.255.255");


		cache = new MyCache();

		portAS = 1800;
		ipmcAS =  InetAddress.getByName("239.255.255.255");
		socket = new MulticastSocket(portAS);
		socket.joinGroup(ipmcAS);

		pwdKeyStore = args[0];
		pwdKey = args[1];

		KeyManager.setCredencials(pwdKeyStore, pwdKey);


		if(args.length > 2 && args.length != 4)
			System.out.println("Insert the port and the ipmcAS");

		if(args.length > 2) {
			ipmcAS = InetAddress.getByName(args[2]);			
			portAS = Integer.parseInt(args[3]);
		}

		String[] pbeConfigs = XMLParser.getPBEconfig();
		cipherSuitePBE = pbeConfigs[0];
		macAlgorithmPBE = pbeConfigs[1];
		cipherProviderPBE = pbeConfigs[2];
		macProviderPBE = pbeConfigs[3];
		macKHashAlgorithm = pbeConfigs[4];

		listenRequests();
	}

	private static void listenRequests() {

		while (true) {

			byte[] packetBytes = new byte[1024];
			DatagramPacket packet = new DatagramPacket(packetBytes, packetBytes.length);


			try {
				socket.receive(packet);
			} catch (IOException e) {
				e.printStackTrace();
			}

			byte[] request = packet.getData();

			try {
				if (authenticate(request))
					sendTicket();
			} catch (Exception e) {
			}


		}
	}

	private static void sendTicket() throws BadPaddingException, Exception {

		try {
			System.out.println("\n-------------------------------------");
			System.out.println("AS - Building ticket for IPMC = " + ipmcRequested);

			TicketAS ticket = createTicket(ipmcRequested);
			byte[] ticketData = encryptTicket(ticket);
			DatagramPacket packet =
					new DatagramPacket(ticketData, ticketData.length, ipmcAS, portAS);

			socket.send(packet);

			System.out.println(ticket.toString());
			System.out.println("\nAS - Sent ticket for IPMC = " + ipmcRequested);
			System.out.println("--------------------------------------\n\n");

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static byte[] encryptTicket(TicketAS ticket) throws  Exception  {

		System.out.println("AS: Encripting Ticket");
		
		Cipher cDec = Cipher.getInstance(cipherSuitePBE, cipherProviderPBE);
		nOnceHeader++;

		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);
		dataStream.write(pbeKey.getEncoded());
		dataStream.writeInt(nOnceHeader);
		dataStream.close();
		byte[] newKeySeed = byteStream.toByteArray();
		pbeKey = new SecretKeySpec(newKeySeed, cipherSuitePBE);
		cDec.init(Cipher.ENCRYPT_MODE, pbeKey, new PBEParameterSpec(salt, iterationCount));

		byteStream = new ByteArrayOutputStream();
		dataStream = new DataOutputStream(byteStream);
		dataStream.writeInt(nOnceHeader);
		int nonceS = new SecureRandom().nextInt();
		dataStream.writeInt(nonceS);
		dataStream.writeUTF(ticket.getCipherConfig());
		dataStream.writeUTF(ticket.getCipherProvider());
		dataStream.writeUTF(ticket.getMacCipher());
		dataStream.writeUTF(ticket.getMacProvider());
		dataStream.writeInt(ticket.getIV().length);
		dataStream.write(ticket.getIV());
		dataStream.writeInt(ticket.getKm().getEncoded().length);
		dataStream.write(ticket.getKm().getEncoded());
		dataStream.writeInt(ticket.getKs().getEncoded().length);
		dataStream.write(ticket.getKs().getEncoded());
		mac_AS.init(macKey_AS);
		mac_AS.update(Utils.toByteArray(nOnceHeader));
		mac_AS.update(Utils.toByteArray(nonceS));
		mac_AS.update(Utils.toByteArrayFromString(ticket.getCipherConfig()));
		mac_AS.update(Utils.toByteArrayFromString(ticket.getCipherProvider()));
		mac_AS.update(Utils.toByteArrayFromString(ticket.getMacCipher()));
		mac_AS.update(Utils.toByteArrayFromString(ticket.getMacProvider()));
		mac_AS.update(Utils.toByteArray(ticket.getIV().length));
		mac_AS.update(ticket.getIV());
		mac_AS.update(Utils.toByteArray(ticket.getKm().getEncoded().length));
		mac_AS.update(ticket.getKm().getEncoded());
		mac_AS.update(Utils.toByteArray(ticket.getKs().getEncoded().length));
		mac_AS.update(ticket.getKs().getEncoded());
		byte[] mac = mac_AS.doFinal();
		dataStream.write(mac);
		dataStream.close();
		byte[] data = byteStream.toByteArray();
		byte[] encData = cDec.doFinal(data);

		return encData;
	}

	private static boolean authenticate(byte[] message) throws Exception {

		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(message));
		String user = istream.readUTF();
		String userPwdHash = XMLParser.getUserHpwd(user);// SHA-512

		if (userPwdHash == null) {
			System.out.println("User isn't registered!");
			return false;
		}
		
		
		nOnceHeader = istream.readInt();
		if(!cache.isValid( nOnceHeader))
			return false;
		else 
			cache.add( nOnceHeader, TIMETOEXPIRE);


		String ipmcHeader = istream.readUTF();
		ipmcRequested = ipmcHeader;


		int clientAuthSize = istream.readInt();
		byte[] clientAuth = new byte[clientAuthSize];
		istream.read(clientAuth);

		byte[] hashedPasswordBytes = userPwdHash.getBytes();
		
		PBEKeySpec pbeSpec = new PBEKeySpec(userPwdHash.toCharArray());
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(cipherSuitePBE, cipherProviderPBE);
		pbeKey = keyFact.generateSecret(pbeSpec);//K -> SHA-512(pwd)
			
		
		
		//Decipher

		Cipher cDec = Cipher.getInstance(cipherSuitePBE, cipherProviderPBE);
		cDec.init(Cipher.DECRYPT_MODE, pbeKey, new PBEParameterSpec(salt, iterationCount));
		byte[] decClientAuthenticator = cDec.doFinal(clientAuth);

		//retrieving contents from decrypted client authenticator

		istream = new DataInputStream(new ByteArrayInputStream(decClientAuthenticator));
		int nonceC = istream.readInt();
		istream.readByte(); 
		String serverIPMC = istream.readUTF();
		int hashedPwdSize = istream.readInt();
		byte[] receivedHashedPwd = new byte[hashedPwdSize];
		istream.read(receivedHashedPwd);

		byte[] receivedMAC = new byte[istream.available()];
		istream.read(receivedMAC);

		
		
		byte[] generatedMACContent = Utils.concatenateByteArrays(Utils.toByteArray(nonceC), receivedHashedPwd); //NONCE || SHA-512(PWD)

		
		mac_AS = Mac.getInstance(macAlgorithmPBE, macProviderPBE);
		macKey_AS =
				new SecretKeySpec(MessageDigest.getInstance(macKHashAlgorithm).digest(generatedMACContent), macAlgorithmPBE); //The key for HMac is the MD5(Nonce C + SHA-512(pwd)))
		mac_AS.init(macKey_AS);

		//  X = Nonce C || IPMC || SHA-512(pwd)
		mac_AS.update(Utils.toByteArray(nonceC)); //adds Nonce from client to HashMac
		mac_AS.update(Utils.toByteArrayFromString(serverIPMC)); //adds multicast ip to HashMac
		byte[] serverMac = mac_AS.doFinal(receivedHashedPwd);//creates MACk (X)

		System.out.println("\n\n---AS Decipher Results---");
		System.out.println("User id = " + user);
		System.out.println("User Password Hash = " + userPwdHash);
		System.out.println("Nonce C = " + nonceC);
		System.out.println("IP Multicast = " + serverIPMC);
		System.out.println("Chave PBE (bytes)= " + Utils.toHex(pbeKey.getEncoded()));
		System.out.println("------------------------\n\n");

		if (!Arrays.equals(serverMac, receivedMAC)) {
			System.out.println("Invalid MAC!");
			return false;
		}


		return validate(ipmcHeader, serverIPMC, nonceC, user);

	}

	private static boolean validate (String ipmcHeader, String serverIPMC, int nonceC, String user) {

	
		if (!ipmcHeader.equals(serverIPMC)) {
			System.out.println("IP distinto do header");
			return false;
		}
		if (nonceC != nOnceHeader) {
			System.out.println("nOnce diferente do header");
			return false;
		}
		if (!XMLParser.checkIfUserHasPerm(user, serverIPMC)) {
			System.out.println("Utilizador sem acesso");
			return false;
		}

		return true;
	}

	private static TicketAS createTicket(String room) throws Exception {

		String[] config = XMLParser.getMultiCastConfig(room);
		String cipherSuite = config[0];
		String  macCipher = config[1];
		String cipherProvider = config[2];
		String macProvider = config[3];
		int cipherKeySize = Integer.parseInt(config[4]);
		int macKeySize = Integer.parseInt(config[5]);

		String cipherAlg = cipherSuite.split("/")[0];

		IvParameterSpec ivSpec = new IvParameterSpec(getIV(room, cipherAlg));

		//read cipher key
		String sKeyEntryName = "sk_" + cipherAlg + "_" + cipherKeySize + "_" + room;
		Key key = getKey(sKeyEntryName, cipherAlg, cipherProvider, cipherKeySize);
		//read mac key
		String macKeyEntryName = "mac_" + macCipher + "_" + macKeySize + "_" + room;
		Key macKey = getKey(macKeyEntryName, macCipher, macProvider, macKeySize);

		TicketAS ticket = new TicketAS(cipherProvider, cipherSuite, macCipher, macProvider, ivSpec, key, macKey);

		return ticket;

	}

	/**
	 * Return the key of the specified entry if it doesn't exist it creates
	 * @param entryName
	 * @param algorithm
	 * @param provider
	 * @param keySize
	 * @return
	 */
	private static Key getKey(String entryName, String algorithm, String provider, int keySize) {

		Key k = null;
		try {
			if((k = KeyManager.getKey(entryName)) == null) {
				k = KeyManager.generateKey(algorithm, provider, keySize);
				KeyManager.storeKey((SecretKey) k, entryName);
			}
		}
		catch (Exception e) {
		}
		return k;
	}

	private static byte[] getIV(String multicastIP, String cipherAlg) {
		byte[] iv = mcIVs.get(multicastIP);

		if (iv == null) {

			switch(cipherAlg) {
			case "AES":
				iv = new byte[16];
				break;
			case "DES":
			case "DESede":
			case "Blowfish":
				iv = new byte[8];
				break;
			default:
				break;
			}

			new SecureRandom().nextBytes(iv);
			mcIVs.put(multicastIP, iv);
		}

		return iv;
	}
}
