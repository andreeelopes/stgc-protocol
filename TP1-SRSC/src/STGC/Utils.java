package STGC;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.spec.IvParameterSpec;

/**
 * Materiais/Labs para SRSC 17/18, Sem-2
 * hj
 **/

/**
 * Classe auxiliar
 * Contem varias funcoes de conversao de formatos como a seguir se documenta
 */
public class Utils {
	private static String	digits = "0123456789abcdef";

	/**
	 * Retorna string hexadecimal a partir de um byte array de certo tamanho
	 *
	 * @param data : bytes a coverter
	 * @param length : numero de bytes no bloco de dados a serem convertidos.
	 * @return  hex : representacaop em hexadecimal dos dados
	 */

	public static String toHex(byte[] data, int length) {
		StringBuffer	buf = new StringBuffer();

		for (int i = 0; i != length; i++) {
			int	v = data[i] & 0xff;

			buf.append(digits.charAt(v >> 4));
			buf.append(digits.charAt(v & 0xf));
		}

		return buf.toString();
	}

	/**
	 * Retorna dados passados como byte array numa string hexadecimal
	 *
	 * @param data : bytes a serem convertidos
	 * @return : representacao hexadecimal dos dados.
	 */
	public static String toHex(byte[] data) {
		return toHex(data, data.length);
	}
	/**
	 * Criar um IV para usar em AES e modo CTR
	 * <p>
	 * IV composto por 4 bytes (numero de emensagem)
	 * 4 bytes de random e um contador de 8 bytes.
	 *
	 * @param messageNumber - Numero da mensagem
	 * @param random - source ou seed para random
	 * @return Vector IvParameterSpec inicializado
	 */
	public static IvParameterSpec createCtrIvForAES(
	    int             messageNumber,
	    SecureRandom    random) {
		byte[]          ivBytes = new byte[16];

		// initially randomize

		random.nextBytes(ivBytes);

		// set the message number bytes

		ivBytes[0] = (byte)(messageNumber >> 24);
		ivBytes[1] = (byte)(messageNumber >> 16);
		ivBytes[2] = (byte)(messageNumber >> 8);
		ivBytes[3] = (byte)(messageNumber >> 0);

		// set the counter bytes to 1

		for (int i = 0; i != 7; i++) {
			ivBytes[8 + i] = 0;
		}

		ivBytes[15] = 1;

		return new IvParameterSpec(ivBytes);
	}
	/**
	 * Converte um byte array de 8 bits numa string
	 *
	 * @param bytes array contendo os caracteres
	 * @param length N. de bytes a processar
	 * @return String que representa os bytes
	 */
	public static String toString(
	    byte[] bytes,
	    int    length) {
		char[]	chars = new char[length];

		for (int i = 0; i != chars.length; i++) {
			chars[i] = (char)(bytes[i] & 0xff);
		}

		return new String(chars);
	}
	/**
	 * Convete um array de caracteres de 8 bits numa string
	 *
	 * @param bytes - Array que contem os caracteres
	 * @return String com a representacao dos bytes
	 */
	public static String toString(
	    byte[]	bytes) {
		return toString(bytes, bytes.length);
	}

	/**
	 * Converte um inteiro para um array de bytes
	 * @param value - o inteiro que se pretende converter
	 * @return array de bytes com a representacao do inteiro
	 */
	public static byte[] toByteArray(int value) {
		return  ByteBuffer.allocate(4).putInt(value).array();
	}


	/***
	 * Converte um array de bytes para um inteiro
	 * @param bytes - o array de bytes que se prentende converter
	 * @return int proveniente do array de bytes
	 */
	public static int fromByteArray(byte[] bytes) {
		return ByteBuffer.wrap(bytes).getInt();
	}

	public static String toStringFromByteArray(byte[] bytes) {
		return new String(Base64.getDecoder().decode(bytes));
	}


	public static byte[] toByteArrayFromString(String str) {
		return Base64.getEncoder().encode(str.getBytes());
	}

	public static byte[] concatenateByteArrays(byte[] a, byte[] b) {

		byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);

		return c;
	}



}



