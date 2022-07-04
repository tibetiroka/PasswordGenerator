package tibetiroka.pwgen;

import lombok.NonNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * Wrapper for all versions of password generators.
 */
public abstract class PasswordGenerator {
	/**
	 * Generates a secure password from the provided information
	 *
	 * @param password The master password
	 * @param site     The site the password is used for
	 * @param username The name of the user on the site
	 * @return The password
	 * @throws Exception If the password cannot be generated
	 */
	public abstract @NonNull byte[] generate(@NonNull byte[] password, @NonNull byte[] site, @NonNull byte[] username) throws Exception;
	
	/**
	 * Performs a one-time XOR operation on the input array. The padding key might be repeated to match the length of the input array.
	 *
	 * @param inputBytes The original input
	 * @param keyBytes   The padding key
	 * @return The padded array
	 */
	protected static @NonNull byte[] xorPad(@NonNull byte[] inputBytes, @NonNull byte[] keyBytes) {
		byte[] result = new byte[inputBytes.length];
		for(int i = 0; i < inputBytes.length; i++) {
			result[i] = (byte) (inputBytes[i] ^ keyBytes[i % keyBytes.length]);
		}
		return result;
	}
	
	/**
	 * Gets the name of the version of this generator
	 *
	 * @return The version name
	 */
	public @NonNull String getVersionName() {
		String name = getClass().getSimpleName();
		if(name.startsWith("PasswordGenerator_")) {
			return name.substring("PasswordGenerator_".length());
		}
		return name;
	}
	
	/**
	 * Creates a salted secure key from the specified salt and password sources.
	 *
	 * @param saltSource     The source of the salt
	 * @param passwordSource The source of the password
	 * @return The salted password
	 */
	protected static @NonNull byte[] createSaltedKey(@NonNull byte[] saltSource, @NonNull byte[] passwordSource) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		byte[] password = xorPad(passwordSource, saltSource);//basic padding because why not
		//
		byte[] iv = secureRandomBytes(password, 256);//creating initialization vector
		//
		byte[] temp = secureRandomBytes(saltSource, 2048);//shuffling init vector
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(temp);
		ArrayUtils.shuffle(iv, random);
		IvParameterSpec spec = new IvParameterSpec(iv);
		//
		byte[] key = secureRandomBytes(xorPad(password, iv), 32);
		//
		Cipher cipher = Cipher.getInstance("AES", BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), spec);
		//
		byte[] bytes = hash(saltSource, password);//reversing to avoid reuse; same security but double the computing time for attackers
		//
		byte[] data = cipher.doFinal(bytes);//getting independent data
		//
		return hash(password, data);
	}
	
	/**
	 * Creates a hash of the specified data using the SHA3-384 algorithm.
	 *
	 * @param data The hashed data
	 * @param salt The random salt to use
	 * @return The hashed data
	 */
	protected static byte[] hash(byte[] data, byte[] salt) throws NoSuchAlgorithmException, NoSuchProviderException {
		MessageDigest digest = MessageDigest.getInstance("SHA3-384", BouncyCastleProvider.PROVIDER_NAME);
		digest.update(salt);
		return digest.digest(data);
	}
	
	/**
	 * Creates a new pseudo-random byte array of the specified length from the specified byte array.
	 *
	 * @param source The source array
	 * @param length The length of the resulting array
	 * @return The random bytes
	 */
	protected static byte[] secureRandomBytes(byte[] source, int length) throws NoSuchAlgorithmException {
		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
		random.setSeed(source);
		byte[] data = new byte[length];
		random.nextBytes(data);
		return data;
	}
	
	/**
	 * Encrypts the specified value using AES. This implementation should not be used with excessively long plaintext.
	 *
	 * @param valueToEnc The plaintext
	 * @param password   The encryption key
	 * @return The encrypted text
	 * @throws NoSuchAlgorithmException  If AES is not supported
	 * @throws NoSuchPaddingException    If PKCS5 padding is not supported
	 * @throws InvalidKeyException       If the provided key is invalid
	 * @throws IllegalBlockSizeException If the length of the provided key is not supported
	 * @throws BadPaddingException       If the code has gone mad
	 * @throws NoSuchProviderException   If BouncyCastle is not found
	 */
	protected static @NonNull byte[] encryptAES(@NonNull byte[] valueToEnc, @NonNull byte[] password) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		Key key = new SecretKeySpec(password, "AES");
		Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding", BouncyCastleProvider.PROVIDER_NAME);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encValue = c.doFinal(valueToEnc);
		String encryptedValue = Base64.getEncoder().encodeToString(encValue);
		return encryptedValue.replaceAll("(?:\\r\\n|\\n\\r|\\n|\\r)", "").getBytes(StandardCharsets.UTF_8);
	}
}
