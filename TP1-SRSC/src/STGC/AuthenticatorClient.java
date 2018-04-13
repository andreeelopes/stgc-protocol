package STGC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.InetAddress;
import java.net.MulticastSocket;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AuthenticatorClient {

	private InetAddress ipmcApp;
	private InetAddress ipmcAS;
	private String id;
	private String pwd;
	private int portAS;
	private Key sKey;
	private MulticastSocket socket;
	private byte[] salt = new byte[] { 0x7d, 0x60, 0x43, 0x5f, 0x02, (byte)0xe9, (byte)0xe0, (byte)0xae }; //change to random?
	private int iterationCount = 2048;
	private Mac mac;
	private SecretKeySpec macKey;
	private int nonceC;
	private String cipherSuitePBE;
	private String macAlgorithmPBE;
	private String macProviderPBE;
	private String cipherProviderPBE;
	private String macKHashAlgorithm;
	private String pwdHashAlgorithm;


	public AuthenticatorClient(InetAddress ipmcApp, InetAddress ipmcAS, int portAS, String id, String pwd) {
		this.ipmcApp = ipmcApp;
		this.ipmcAS = ipmcAS;
		this.id = id;
		this.pwd = pwd;
		this.portAS = portAS;

		try {

			socket = new MulticastSocket(portAS);
			socket.joinGroup(ipmcAS);

		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	public TicketAS authenticate() {

		byte[] pbeMessage = null;
		TicketAS ticket = null;
		try {

			String[] pbeConfigs = XMLParser.getPBEconfig();
			cipherSuitePBE = pbeConfigs[0];
			macAlgorithmPBE = pbeConfigs[1];
			cipherProviderPBE = pbeConfigs[2];
			macProviderPBE = pbeConfigs[3];
			macKHashAlgorithm = pbeConfigs[4];
			pwdHashAlgorithm = pbeConfigs[5];
			
			pbeMessage = cipherMessage(ipmcApp, id, pwd);
			sendPBEMessage(pbeMessage, ipmcAS, portAS);
			ticket = receiveTicket();
			
			System.out.println("\n----TICKET RECEIVED FROM AS----");
			System.out.println(ticket.toString());
			System.out.println("-------------------------------\n");


		} catch (Exception e) {
			e.printStackTrace();
		}

		return ticket;
	}


	private void sendPBEMessage(byte[] pbeMessage, InetAddress ipmcAS, int portAS) {
		try {

			DatagramPacket packet = new DatagramPacket(pbeMessage, pbeMessage.length, ipmcAS, portAS);

			socket.send(packet);

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private TicketAS receiveTicket() {
		TicketAS ticket = null;
		byte[] buf = new byte[1500];
		while (ticket == null) {
			DatagramPacket packet = new DatagramPacket(buf, buf.length);
			try {
				socket.receive(packet);
			} catch (IOException e) {
				e.printStackTrace();
			}
			ticket = decipherMessage(packet.getData(), packet.getLength());
		}
		return ticket;
	}


	private TicketAS readTicketMessage(byte[] message, int size) throws Exception {
		try {

			Cipher cEnc = Cipher.getInstance(cipherSuitePBE, cipherProviderPBE);
			ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
			DataOutputStream dataStream = new DataOutputStream(byteStream);
			dataStream.write(sKey.getEncoded());
			dataStream.writeInt(nonceC + 1);
			dataStream.close();
			byte[] newKeySeed = byteStream.toByteArray();

			Key newsKey = new SecretKeySpec(newKeySeed, cipherSuitePBE);
			cEnc.init(Cipher.DECRYPT_MODE, newsKey, new PBEParameterSpec(salt, iterationCount));
			byte[] decMessage = cEnc.doFinal(message, 0, size);

			DataInputStream istream = new DataInputStream(new ByteArrayInputStream(decMessage));
			int nOnceMessage = istream.readInt();
			if (nOnceMessage != (nonceC + 1))
				return null;
			int nOnceServer = istream.readInt();
			String cipherConfig = istream.readUTF();
			String cipherProvider = istream.readUTF();
			String macCipher = istream.readUTF();
			String macProvider = istream.readUTF();
			int iVsize = istream.readInt();
			byte[] iv = new byte[iVsize];
			istream.read(iv);
			int kMsize = istream.readInt();
			byte[] kM = new byte[kMsize];
			istream.read(kM);
			int kSsize = istream.readInt();
			byte[] kS = new byte[kSsize];
			istream.read(kS);
			byte[] messageMac = new byte[istream.available()];
			istream.read(messageMac);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			Key keyS = new SecretKeySpec(kS, cipherConfig.split("/")[0]);
			Key keyM = new SecretKeySpec(kM, macCipher);

			mac.init(macKey);
			mac.update(Utils.toByteArray(nOnceMessage));
			mac.update(Utils.toByteArray(nOnceServer));
			mac.update(Utils.toByteArrayFromString(cipherConfig));
			mac.update(Utils.toByteArrayFromString(cipherProvider));
			mac.update(Utils.toByteArrayFromString(macCipher));
			mac.update(Utils.toByteArrayFromString(macProvider));
			mac.update(Utils.toByteArray(iv.length));
			mac.update(iv);
			mac.update(Utils.toByteArray(kM.length));
			mac.update(kM);
			mac.update(Utils.toByteArray(kS.length));
			mac.update(kS);
			
			byte[] macBytes = mac.doFinal();
			
			if (!Arrays.equals(macBytes, messageMac)) {
				System.out.println("Invalid MAC!");
				return null;
			}
			
			return new TicketAS(cipherProvider,  cipherConfig,  macCipher,  macProvider,
					ivSpec, keyS, keyM);
		
		} catch (Exception e) {

			return null;
		}

	}
	private TicketAS decipherMessage(byte[] cipherText, int size) {


		TicketAS ticket = null;

		try {
			ticket = readTicketMessage(cipherText,  size);
		} catch (Exception e) {
			e.printStackTrace();
		}



		return ticket;
	}

	private byte[] cipherMessage(InetAddress ipmcApp, String clientID, String password) throws Exception {

		nonceC = new SecureRandom().nextInt();
		String ipmcAppString = ipmcApp.getHostAddress();
		MessageDigest hashMACPwdAlg = MessageDigest.getInstance(macKHashAlgorithm);
		MessageDigest hashPBEPwdAlg = MessageDigest.getInstance(pwdHashAlgorithm);

		byte[] hashedPwd = hashPBEPwdAlg.digest(password.getBytes());
		
		
		PBEKeySpec pbeSpec = new PBEKeySpec(Utils.getStringFromDigest(hashedPwd).toCharArray());
		SecretKeyFactory keyFact = SecretKeyFactory.getInstance(cipherSuitePBE, cipherProviderPBE);
		sKey = keyFact.generateSecret(pbeSpec);//K -> SHA-512(pwd)
						
		
		byte[] macKeyContent = Utils.concatenateByteArrays(Utils.toByteArray(nonceC), hashedPwd); //NONCE || SHA-512(PWD)

		
		
		mac = Mac.getInstance(macAlgorithmPBE, macProviderPBE);
		macKey =
				new SecretKeySpec(hashMACPwdAlg.digest(macKeyContent), macAlgorithmPBE); //The key for HMac is the MD5(Nonce C + SHA-512(pwd)))
		//  X = Nonce C || IPMC || SHA-512(pwd)
		mac.init(macKey);
		mac.update(Utils.toByteArray(nonceC)); //adds Nonce from client to HashMac
		mac.update(Utils.toByteArrayFromString(ipmcAppString)); //adds multicast ip to HashMac
		byte[] macBytes = mac.doFinal(hashedPwd);//creates MACk (X)

		Cipher cEnc = Cipher.getInstance(cipherSuitePBE, cipherProviderPBE);
		cEnc.init(Cipher.ENCRYPT_MODE, sKey, new PBEParameterSpec(salt, iterationCount));
		// E [ K, ( Nonce C || IPMC || SHA-512(pwd) || MACk (X) ) ]
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);
		byte[] space = new byte[] {0x00};
		
		dataStream.writeInt(nonceC);
		dataStream.write(space);
		dataStream.writeUTF(ipmcAppString);
		dataStream.writeInt(hashedPwd.length);
		dataStream.write(hashedPwd);
		dataStream.write(macBytes);
		dataStream.close();
		
		byte[] data = byteStream.toByteArray();

		byte[] encClientAuthenticator =  cEnc.doFinal(data);
		//message to be sent to AS
		//String message = clientID + nonceC + ipmc + Utils.toStringFromByteArray(clientAuthenticator); //Cliente ID || NonceC || IPMC || AutenticadorC

		byteStream = new ByteArrayOutputStream();
		dataStream = new DataOutputStream(byteStream);
		dataStream.writeUTF(clientID);
		dataStream.writeInt(nonceC);
		dataStream.writeUTF(ipmcAppString);
		dataStream.writeInt(encClientAuthenticator.length);
		dataStream.write(encClientAuthenticator);
		dataStream.close();

		byte[] message = byteStream.toByteArray();

		
		
		System.out.println("\n\n---Authenticator Decipher Results---");
		System.out.println("User id = " + clientID);
		System.out.println("User Password Hash = " + Utils.getStringFromDigest(hashedPwd));
		System.out.println("Nonce C = " + nonceC);
		System.out.println("IP Multicast = " + ipmcAppString);
		System.out.println("PBE Key = " + Utils.toHex(sKey.getEncoded()));
		System.out.println("------------------------\n\n");
		

		return message;
	}


}
