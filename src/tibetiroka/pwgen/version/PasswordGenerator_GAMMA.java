package tibetiroka.pwgen.version;

import tibetiroka.pwgen.PasswordGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Random;

public class PasswordGenerator_GAMMA extends PasswordGenerator {
	@Override
	public String generate(String secret, String site, String username) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException {
		site = base64(site);
		username = base64(username);
		secret = base64(secret);
		ArrayList<Integer> mash = new ArrayList<>();
		String result = "";
		long value = 0;
		{
			SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
			rand.setSeed(site.getBytes());
			for(int i = 0; i < site.length(); i++) {
				value += site.charAt(i) * rand.nextInt(100);
			}
		}
		{
			Random random = new Random();
			random.setSeed(value);
			for(int i = 0; i < username.length(); i++) {
				int k = random.nextInt(i + 1) * username.charAt(username.length() - i - 1);
				if(k > 10) {
					mash.add(k);
				}
			}
		}
		{
			byte[] pw = to32(secret);
			String text = Arrays.toString(mash.toArray());
			byte[] data = text.getBytes(StandardCharsets.US_ASCII);
			data = xorPad(data, secret.getBytes(StandardCharsets.US_ASCII));
			result = new String(encryptAES(data, pw), StandardCharsets.US_ASCII);
		}
		result = hash(result);
		return result;
	}
	
	private static String hash(String text) throws NoSuchAlgorithmException {
		byte[] bytesOfMessage = text.getBytes(StandardCharsets.US_ASCII);
		
		MessageDigest md = MessageDigest.getInstance("SHA3-512");
		byte[] digest = md.digest(bytesOfMessage);
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		long mult = 1;
		for(byte b : digest) {
			mult *= b;
			mult += b;
		}
		random.setSeed(mult);
		digest = Base64.getEncoder().encode(digest);
		ArrayList<Byte> list = new ArrayList<>();
		for(byte b : digest) {
			list.add(b);
		}
		Collections.shuffle(list, random);
		digest = new byte[32];
		for(int i = 0; i < digest.length; i++) {
			digest[i] = list.get(i);
		}
		return new String(digest, StandardCharsets.US_ASCII);
	}
}
