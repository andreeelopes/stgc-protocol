package STGC;

public class MessageHeader {

	private byte version;
	private byte type;
	private int size;
	
	
	public MessageHeader(byte version, byte type, int size) {
		this.version = version;
		this.type = type;
		this.size = size;
	}
	
	public byte getVersion() {
		return version;
	}
	
	public void setVersion(byte version) {
		this.version = version;
	}
	
	public byte getType() {
		return type;
	}
	
	public void setType(byte type) {
		this.type = type;
	}
	
	public int getSize() {
		return size;
	}
	
	public void setSize(int size) {
		this.size = size;
	}
	
	
}
