package tibetiroka.pwgen;

import lombok.NonNull;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Manages storing login credentials on the system. The actual credentials are never stored for obvious safety reasons, however salts might be stored to provide basic error correction capabilities.
 */
public class CredentialManager {
	/**
	 * Gets the file where the credential hashes are stored.
	 *
	 * @return The hash file
	 */
	private static @NonNull File getHashFile() {
		return new File("hashes_" + Configuration.getHashSecurity().name().toLowerCase() + ".dat");
	}
	
	/**
	 * Gets the encryption key that is used for storing password hashes. If no such key is found, a new key is created and stored.
	 *
	 * @return The encryption key
	 */
	private static @NonNull PublicKey getEncryptionKey() {
		File keyFile = new File("public_" + Configuration.getHashSecurity().name().toLowerCase() + ".x509");
		if(keyFile.exists()) {
			try {
				byte[] publicKeyBytes = Files.readAllBytes(keyFile.toPath());
				KeyFactory keyFactory = KeyFactory.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
				EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
				PublicKey key = keyFactory.generatePublic(publicKeySpec);
				if(key instanceof RSAPublicKey rsaKey) {
					if(rsaKey.getModulus().bitLength() == Configuration.getHashSecurity().getRsaKeySize()) {
						return key;
					}
					System.err.println("Invalid key found for hash storage");
				}
			} catch(Exception e) {
				e.printStackTrace();
			}
		} else {
			System.out.println("No encryption key found for hash storage");
		}
		keyFile.delete();
		getHashFile().delete();
		try {
			System.out.println("Generating encryption key for hash storage." + switch(Configuration.getHashSecurity()) {
				case LOW -> "";
				case MEDIUM -> " This might take some time.";
				case HIGH -> " This might take up to 30 minutes depending on your hardware.";
				case OVERKILL -> "This might take hours in your current configuration. It is recommended to downgrade your security level or use an externally generated key.";
				case CRAZY -> "You do you, buddy.";
			});
			System.out.println("This action is only performed once, unless you change your configuration.");
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
			generator.initialize(Configuration.getHashSecurity().getRsaKeySize());
			PublicKey key = generator.generateKeyPair().getPublic();
			Files.write(keyFile.toPath(), key.getEncoded(), StandardOpenOption.CREATE_NEW);
			getHashFile().createNewFile();
			return key;
		} catch(IOException | NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new RuntimeException(e);
		}
	}
	
	/**
	 * Checks whether the specified hash is stored in the hash storage.
	 *
	 * @param hash The hash to check
	 * @return True if the hash is present, false otherwise
	 * @throws IOException If the hash storage file is not present or cannot be read from
	 */
	public static boolean verifyHash(@NonNull String hash) throws IOException {
		if(!getHashFile().exists()) {
			return false;
		}
		BufferedReader reader = new BufferedReader(new FileReader(getHashFile()));
		for(String line = reader.readLine(); line != null; line = reader.readLine()) {
			if(hash.equals(line)) {
				return true;
			}
		}
		return false;
	}
	
	/**
	 * Saves the specified hash to the hash storage. It is assumed that the hash is not already present in the file.
	 *
	 * @param hash The hash to save
	 */
	public static void saveHash(@NonNull String hash) throws IOException {
		if(!getHashFile().exists()) {
			getHashFile().createNewFile();
		}
		Files.writeString(getHashFile().toPath(), hash + System.lineSeparator(), StandardOpenOption.APPEND);
	}
	
	/**
	 * Generates a secure hash from the specified username and password.
	 *
	 * @param username The username
	 * @param password The password
	 * @return The hash
	 * @throws NoSuchAlgorithmException  If RSA, SHA3-256 or SHA1PRNG is not supported
	 * @throws NoSuchProviderException   If BouncyCastle is not found
	 * @throws NoSuchPaddingException    If textbook RSA is not supported
	 * @throws IllegalBlockSizeException If the RSA block site is not supported
	 * @throws BadPaddingException       If the code has gone mad
	 * @throws InvalidKeyException       If the key is not appropriate for the cipher
	 */
	public static @NonNull String generateHash(@NonNull byte[] username, @NonNull byte[] password) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
		SecureRandom saltRandom = SecureRandom.getInstance("SHA1PRNG");
		saltRandom.setSeed(username);
		byte[] salt = new byte[Configuration.getHashSecurity().getHashSaltSize()];
		saltRandom.nextBytes(salt);
		//
		SecureRandom pwRandom = SecureRandom.getInstance("SHA1PRNG");
		pwRandom.setSeed(password);
		byte[] pwData = new byte[256];
		pwRandom.nextBytes(pwData);
		//
		ArrayUtils.shuffle(salt, pwRandom);
		ArrayUtils.shuffle(pwData, saltRandom);
		//
		MessageDigest digest = MessageDigest.getInstance("SHA3-256", BouncyCastleProvider.PROVIDER_NAME);
		digest.update(password);
		byte[] bytes = digest.digest(salt);
		//
		Cipher cipher = Cipher.getInstance("RSA", BouncyCastleProvider.PROVIDER_NAME);
		cipher.init(Cipher.PUBLIC_KEY, getEncryptionKey());
		bytes = cipher.doFinal(bytes);
		//
		return ArrayUtils.toBase64String(bytes);
	}
}