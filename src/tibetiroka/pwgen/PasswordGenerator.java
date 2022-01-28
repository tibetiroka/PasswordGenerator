package tibetiroka.pwgen;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public abstract class PasswordGenerator {
	public PasswordGenerator() {
	
	}
	
	public abstract String generate(String password, String site, String username) throws Exception;
	
	protected static String xorPad(String input, String key) {
		byte[] inputBytes = input.getBytes(StandardCharsets.US_ASCII);
		byte[] keyBytes = key.getBytes(StandardCharsets.US_ASCII);
		return new String(xorPad(inputBytes, keyBytes), StandardCharsets.US_ASCII);
	}
	
	protected static byte[] xorPad(byte[] inputBytes, byte[] keyBytes) {
		byte[] result = new byte[inputBytes.length];
		for(int i = 0; i < inputBytes.length; i++) {
			result[i] = (byte) (inputBytes[i] ^ keyBytes[i % keyBytes.length]);
		}
		return result;
	}
	
	protected static byte[] to32(String text) {
		byte[] bytes = new byte[32];
		byte[] t = text.getBytes(StandardCharsets.US_ASCII);
		for(int i = 0; i < t.length; i++) {
			byte b = t[i];
			if(i > 32) {
				b = (byte) (b * Math.sqrt(52567));
			}
			bytes[i % 32] += b;
		}
		return bytes;
	}
	
	
	protected static Key generateKey(byte[] keyBytes) {
		return new SecretKeySpec(keyBytes, "AES");
	}
	
	protected static byte[] encryptAES(byte[] valueToEnc, byte[] password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Key key = generateKey(password);
		Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encValue = c.doFinal(valueToEnc);
		String encryptedValue = Base64.getEncoder().encodeToString(encValue);
		return encryptedValue.replaceAll("(?:\\r\\n|\\n\\r|\\n|\\r)", "").getBytes(StandardCharsets.UTF_8);
	}
	
	protected static String base64(String s) {
		return new String(Base64.getEncoder().encode(s.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8);
	}
}
