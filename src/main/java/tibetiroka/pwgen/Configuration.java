package tibetiroka.pwgen;

import lombok.Getter;
import lombok.Setter;

/**
 * Configures the behaviour of the password generators and the credential manager.
 */
public class Configuration {
	/**
	 * The level of security to use in the hash storage
	 */
	@Getter
	@Setter
	private static SecurityLevel hashSecurity = SecurityLevel.HIGH;
	/**
	 * Whether to use the hash storage
	 */
	@Getter
	@Setter
	private static boolean useHashStorage = true;
	/**
	 * Whether to force a safe console for password input. Safe consoles support echo-less input.
	 */
	@Getter
	@Setter
	private static boolean forceSafeConsole = false;
	/**
	 * Whether the system console is a safe console
	 */
	@Getter
	@Setter
	private static boolean safeConsole = System.console() != null;
	/**
	 * Whether to copy the created password to the clipboard when it is generated
	 */
	@Getter
	@Setter
	private static boolean copyPasswordToClipboard = true;
	/**
	 * Whether to write the created password to the standard output when it is generated
	 */
	@Getter
	@Setter
	private static boolean echoPassword = true;
	
	/**
	 * The list of supported security levels.
	 */
	public enum SecurityLevel {
		/**
		 * Provides some minimal amount of security. In general, the data will not be exposed in plain text, however an attacker will probably be able to access sensitive information.
		 */
		LOW(1024, 16),
		/**
		 * Provides adequate security for most applications. Provides a relatively good trade-off between speed and security. Recommended for network applications.
		 */
		MEDIUM(4096, 64),
		/**
		 * Provides serious security that is feasible for nearly all cases. Provides a good trade-off between speed and security, although it might have a relatively high first-time cost. Recommended for storing sensitive data.
		 */
		HIGH(16384, 256),
		/**
		 * Provides a level of security where your only issue is going to be computing power for actually using it.
		 */
		OVERKILL(65536, 1024),
		/**
		 * Good luck with generating an initial RSA key. Should work afterwards though. Never bothered to test.
		 */
		CRAZY(1048576, 12384);
		/**
		 * The size of the RSA keys that are generated for this security level
		 */
		@Getter
		private final int rsaKeySize;
		/**
		 * The recommended site of salt for this security level
		 */
		@Getter
		private final int hashSaltSize;
		
		/**
		 * Creates a new security level.
		 *
		 * @param rsaKeySize The size of the used RSA keys
		 */
		SecurityLevel(int rsaKeySize, int hashSaltSize) {
			this.rsaKeySize = rsaKeySize;
			this.hashSaltSize = hashSaltSize;
		}
	}
}
