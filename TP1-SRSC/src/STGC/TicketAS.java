package STGC;

import java.io.Serializable;
import java.security.Key;

import javax.crypto.spec.IvParameterSpec;

public class TicketAS implements Serializable {


	private static final long serialVersionUID = 1L;

	private Key ks; //symmetric encryption key
	private Key km; //key for MAC
	private byte[] ivSpec;
	private String cipherProvider;

	private String cipherSuite;
	private String macCipher;
	private String macProvider;
	private String cipherMode;


	public TicketAS(String cipherProvider, String cipherConfig, String macCipher, String macProvider,
			IvParameterSpec ivSpec, Key ks, Key km) {
		this.ks = ks;
		this.km = km;
		this.ivSpec = ivSpec.getIV();
		this.cipherProvider = cipherProvider;
		this.cipherSuite = cipherConfig;
		this.macCipher = macCipher;
		this.macProvider = macProvider;
		this.cipherMode = cipherSuite.split("/")[1];
	}

	public String getCipherProvider() {
		return cipherProvider;
	}

	public String getMacCipher() {
		return macCipher;
	}

	public String getMacProvider() {
		return macProvider;
	}

	public Key getKs() {
		return ks;
	}

	public Key getKm() {
		return km;
	}

	public byte[] getIV() {
		return ivSpec;
	}

	public String getCipherConfig() {
		return cipherSuite;
	}
	
	public String getCipherMode() {
		return cipherMode;
	}

	@Override
	public String toString() {
		return "TicketAS [ks=" + Utils.toHex(ks.getEncoded()) + ", km=" + Utils.toHex(km.getEncoded())
		+ ", ivSpec=" + Utils.toHex(ivSpec) + ", cipherProvider=" + cipherProvider
		+ ", cipherConfig=" + cipherSuite + ", macCipher=" + macCipher
		+ ", macProvider=" + macProvider + "]";
	}



}
