package tibetiroka.pwgen.version;

import tibetiroka.pwgen.PasswordGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Random;

class PasswordGenerator_ALPHA extends PasswordGenerator {
	public PasswordGenerator_ALPHA() {
	
	}
	
	@Override
	public String generate(String secret, String site, String username) throws NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchPaddingException {
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
			result = new String(encryptAES(data, pw), StandardCharsets.US_ASCII);
		}
		result = resize(result);
		result = scramble(result);
		return result;
	}
	
	private static String scramble(String text) throws NoSuchAlgorithmException {
		SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
		int lo = text.charAt(text.length() - 6);
		int hi = text.charAt(15);
		long val = (((long) hi) << 32) | (lo & 0xffffffffL);
		ArrayList<Character> list = new ArrayList<>();
		for(char c : text.toCharArray()) {
			list.add(c);
		}
		rand.setSeed(val);
		Collections.shuffle(list, rand);
		StringBuilder builder = new StringBuilder();
		for(Character character : list) {
			builder.append(character);
		}
		return builder.toString();
	}
	
	private static String resize(String text) {
		final int max = 32;
		double last = 0;
		double ratio = Math.sqrt(53);
		StringBuilder sb = new StringBuilder(text);
		while(sb.length() > max) {
			last += ratio;
			last = last % sb.length();
			sb.deleteCharAt((int) last);
		}
		return sb.toString();
	}
}
