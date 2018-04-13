package STGC;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;


import java.net.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;


import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;


public class STGCMulticastSocket extends MulticastSocket {

	private Cipher cipher;
	private Key key;
	private IvParameterSpec ivSpec;
	Key macKey;
	Mac mac;
	private TicketAS ticket;
	private static final int TIMETOEXPIRE= 10000;
	//STGC protocol available payload types
	private static final char APPLICATION_TYPE = 'M';
	private static final char STGC_TYPE = 'S';

	private byte[] version = new byte[] {0x11};
	private MyCache cache;

	public STGCMulticastSocket(int port, InetAddress ipmcApp, InetAddress ipmcAS, int portAS, String id, String pwd) throws IOException {
		super(port);
		cache=new MyCache();
		AuthenticatorClient auth = new AuthenticatorClient(ipmcApp, ipmcAS, portAS, id, pwd);


		ticket = auth.authenticate();
		ivSpec = new IvParameterSpec(ticket.getIV());
		try {
			mac = Mac.getInstance(ticket.getMacCipher(), ticket.getMacProvider());
			cipher = Cipher.getInstance(ticket.getCipherConfig(), ticket.getCipherProvider());
		} catch (Exception e) {

		}
		macKey = ticket.getKm();
		key = ticket.getKs();
	}


	@Override
	public void send(DatagramPacket packet) {

		byte[] cipherdata = null;

		try {
			cipherdata = encrypt(packet.getData());

			packet.setData(cipherdata);

			super.send(packet);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	public void send(DatagramPacket packet, char payloadType) {

		switch(payloadType) {
		case APPLICATION_TYPE:

			try {

				packet.setData(createHeaderAndAddMessage(packet.getData(), APPLICATION_TYPE));
				super.send(packet);

			} catch (IOException e) {
				e.printStackTrace();
			}

			break;
		case STGC_TYPE:
			this.send(packet);
			break;
		default:
			System.out.println("Invalid Payload Type = " + payloadType);
			break;
		}
	}

	@Override
	public void receive(DatagramPacket packet) throws IOException {		

		int packetSize = packet.getLength();
		super.receive(packet);

		byte[] messageData = null;
		byte[] packetData = new byte[packetSize];//packet data to be receive ('returned' from this method)
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(packet.getData()));
		MessageHeader header = getMessageHeader(istream);

		byte version = header.getVersion();
		byte payloadType = header.getType();
		int payloadSize = header.getSize();

		byte[] payload = new byte[payloadSize];
		istream.readFully(payload);

		if(version == this.version[0]) { // if valid payload version

			//validate payload type
			switch(payloadType) {
			case STGC_TYPE:
				try {

					messageData = this.decrypt(payload, payload.length);

				} catch (Exception e) {

					e.printStackTrace();
				}
				break;
			case APPLICATION_TYPE:
				messageData = packet.getData();
				break;
			default:
				System.out.println("Invalid Payload Type = " + payloadType);
				break;
			}
		}

		System.arraycopy(messageData, 0, packetData, 0, messageData.length);
		packet.setData(packetData);

	}

	public byte[] encrypt(byte[] message){

		// Mp = [id || nonce || M]
		byte[] cipherText = null;

		try {

			if(ticket.getCipherMode().equals("ECB"))//ECB doesn't use inicialization vector
				cipher.init(Cipher.ENCRYPT_MODE, key);
			else
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
			dataStream.write(machash);
			dataStream.close();
			byte[] Text = byteStream.toByteArray();

			 cipherText=cipher.doFinal(Text);
			//System.out.println(Utils.toHex(plainText));


		} catch (InvalidKeyException | InvalidAlgorithmParameterException
				| IllegalBlockSizeException 
				| BadPaddingException | IllegalStateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return createHeaderAndAddMessage(cipherText, STGC_TYPE);

	}


	private MessageHeader getMessageHeader(DataInputStream packetStream) {

		byte version = 0;
		byte type = 0;
		int size = 0;

		try {
			version = packetStream.readByte();
			packetStream.readByte();
			type = packetStream.readByte();
			packetStream.readByte();
			size = packetStream.readShort();

		} catch (IOException e) {
			e.printStackTrace();
		}

		return new MessageHeader(version, type, size);
	}

	/**
	 * 
	 * @param cypherText
	 * @param lenght - length of the cyphertext
	 * @return
	 * @throws Exception
	 */
	public byte[] decrypt(byte[] cypherText,int lenght) throws Exception {

		if(ticket.getCipherMode().equals("ECB"))//ECB doesn't use inicialization vector
			cipher.init(Cipher.DECRYPT_MODE, key);
		else
			cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

		byte[] plainText = cipher.doFinal(cypherText);//plainText contains both the message and the MAC
		DataInputStream istream = new DataInputStream(new ByteArrayInputStream(plainText));
		
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

	private byte[] createHeaderAndAddMessage(byte[] payload, char payloadType) {
		ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
		DataOutputStream dataStream = new DataOutputStream(byteStream);

		byte[] space = new byte[] {0x00};

		try {

			dataStream.write(version);
			dataStream.write(space);
			dataStream.write(payloadType);
			dataStream.write(space);
			dataStream.writeShort(payload.length);
			dataStream.write(payload);
			dataStream.close();

		} catch (IOException e) {
			e.printStackTrace();
		}

		return byteStream.toByteArray();
	}
}
