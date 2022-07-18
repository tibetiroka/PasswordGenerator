package tibetiroka.pwgen;

import lombok.NonNull;
import lombok.SneakyThrows;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import tibetiroka.pwgen.Configuration.SecurityLevel;
import tibetiroka.pwgen.version.VersionManager;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.DataFlavor;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.Security;
import java.util.Scanner;

public class Main {
	@SneakyThrows
	public static void main(String[] args) {
		Security.setProperty("crypto.policy", "unlimited");
		PasswordGenerator generator = null;
		byte[] site = null;
		byte[] username = null;
		byte[] password = null;
		for(String arg : args) {
			String[] parts = arg.split("=");
			try {
				switch(parts[0]) {
					case "pwgen.config.hashSecurity" -> Configuration.setHashSecurity(SecurityLevel.valueOf(parts[1]));
					case "pwgen.config.useHashStorage" -> Configuration.setUseHashStorage(Boolean.parseBoolean(parts[1]));
					case "pwgen.config.forceSafeConsole" -> Configuration.setForceSafeConsole(Boolean.parseBoolean(parts[1]));
					case "pwgen.config.usernameSensitive" -> Configuration.setUsernameSensitive(Boolean.parseBoolean(parts[1]));
					case "pwgen.config.siteSensitive" -> Configuration.setSiteSensitive(Boolean.parseBoolean(parts[1]));
					case "pwgen.config.isSafeConsole" -> Configuration.setSafeConsole(Boolean.parseBoolean(parts[1]));
					case "pwgen.config.copyPasswordToClipboard" -> Configuration.setCopyPasswordToClipboard(Boolean.parseBoolean(parts[1]));
					case "pwgen.config.echoPassword" -> Configuration.setEchoPassword(Boolean.parseBoolean(parts[1]));
					case "pwgen.generator.version" -> generator = VersionManager.getGenerator(parts[1]);
					case "pwgen.site" -> site = PasswordGenerator.secureRandomBytes(parts[1].getBytes(StandardCharsets.UTF_8), 256);
					case "pwgen.username" -> username = PasswordGenerator.secureRandomBytes(parts[1].getBytes(StandardCharsets.UTF_8), 256);
					case "pwgen.password" -> password = PasswordGenerator.secureRandomBytes(parts[1].getBytes(StandardCharsets.UTF_8), 256);
				}
			} catch(Exception e) {
				System.err.println("Invalid value in " + arg);
			}
		}
		Security.addProvider(new BouncyCastleProvider());
		generate(generator, site, username, password);
	}
	
	/**
	 * Generates a new password
	 *
	 * @param generator The version of generator to use, or null to prompt the user
	 * @param site      The site to generate password for, or null to prompt the user
	 * @param username  The username to use, or null to prompt the user
	 * @param password  The password to use, or null to prompt the user
	 * @throws Exception If the password cannot be generated
	 */
	public static void generate(PasswordGenerator generator, byte[] site, byte[] username, byte[] password) throws Exception {
		if((!Configuration.isCopyPasswordToClipboard()) && (!Configuration.isEchoPassword())) {
			System.out.println("All password output forms are turned off, aborting");
			System.exit(0);
		}
		Scanner sc = new Scanner(System.in);
		System.out.println("Password Generator");
		if(generator == null) {
			System.out.println("Please name the version you want to use (leave blank for latest version)");
			do {
				String version = sc.nextLine();
				if(version.trim().isEmpty()) {
					version = VersionManager.GeneratorVersion.values()[VersionManager.GeneratorVersion.values().length - 1].name();
					System.out.println("Using version " + version);
				}
				generator = VersionManager.getGenerator(version);
				if(generator == null) {
					System.out.println("Unknown version");
				}
			} while(generator == null);
		} else {
			System.out.println("Using version " + generator.getVersionName());
		}
		//
		if(site == null) {
			site = PasswordGenerator.secureRandomBytes(prompt("Please name the site or application", Configuration.isSiteSensitive()), 256);
		}
		if(username == null) {
			username = PasswordGenerator.secureRandomBytes(prompt("Please choose your preferred username:", Configuration.isUsernameSensitive()), 256);
		}
		if(password == null) {
			password = PasswordGenerator.secureRandomBytes(promptPassword("Please type in your personal secret code:"), 256);
		}
		//
		if(Configuration.isUseHashStorage()) {
			String hash = CredentialManager.generateHash(username, password);
			if(!CredentialManager.verifyHash(hash)) {
				if(!promptAnswer("Unknown username/password combination. Are you sure it is correct? (Y/n)")) {
					return;
				}
				if(promptAnswer("Would you like to save it? (Y/n)")) {
					if(Configuration.isSafeConsole()) {
						byte[] pw2 = PasswordGenerator.secureRandomBytes(promptPassword("Please repeat your password"), 256);
						String hash2 = CredentialManager.generateHash(username, pw2);
						if(hash.equals(hash2)) {
							CredentialManager.saveHash(hash);
						} else {
							System.out.println("The passwords do not match.");
							return;
						}
					} else {
						CredentialManager.saveHash(hash);
					}
				}
			}
		}
		char[] result = ArrayUtils.toCharArray(generator.generate(password, site, username));
		if(Configuration.isCopyPasswordToClipboard()) {
			Clipboard c = Toolkit.getDefaultToolkit().getSystemClipboard();
			StringSelection testData = new StringSelection(new String(result));
			c.setContents(testData, testData);
			Transferable t = c.getContents(null);
			if(t.isDataFlavorSupported(DataFlavor.stringFlavor)) {
				t.getTransferData(DataFlavor.stringFlavor);
			}
			System.out.println("Copied password to clipboard");
		}
		if(Configuration.isEchoPassword()) {
			System.out.println("Your password is:");
			System.out.println(result);
		}
	}
	
	/**
	 * Prompts for a yes/no answer for a question.
	 *
	 * @param prompt The question
	 * @return True if the answer is yes
	 */
	private static boolean promptAnswer(@NonNull String prompt) {
		Scanner sc = new Scanner(System.in);
		while(true) {
			System.out.println(prompt);
			String s = sc.nextLine();
			if(s.equalsIgnoreCase("y")) {
				return true;
			} else if(s.equalsIgnoreCase("n")) {
				return false;
			}
		}
	}
	
	/**
	 * Prompts for input based on the provided condition. If {@code password} is true, the password input is used. Otherwise, the standard input is used for the prompt.
	 *
	 * @param prompt   The prompting text
	 * @param password Whether the input is a password
	 * @return The input
	 * @throws IOException If {@link #promptPassword(String)} cannot be performed
	 */
	private static @NonNull byte[] prompt(@NonNull String prompt, boolean password) throws IOException {
		if(password) {
			return promptPassword(prompt);
		} else {
			return promptInput(prompt);
		}
	}
	
	/**
	 * Prompts for single-line input
	 *
	 * @param prompt The prompt
	 * @return The input
	 */
	private static @NonNull byte[] promptInput(@NonNull String prompt) {
		Scanner sc = new Scanner(System.in);
		System.out.println(prompt);
		return sc.nextLine().getBytes(StandardCharsets.UTF_8);
	}
	
	/**
	 * Prompts for single-line password input
	 *
	 * @param prompt The prompt
	 * @return The input
	 */
	private static @NonNull byte[] promptPassword(@NonNull String prompt) throws IOException {
		checkConsole();
		System.out.println(prompt);
		if(Configuration.isSafeConsole()) {
			return ArrayUtils.toByteArray(System.console().readPassword());
		} else {
			ByteArrayOutputStream stream = new ByteArrayOutputStream();
			byte[] buffer = new byte[1];
			while(true) {
				int amount = System.in.read(buffer);
				if(amount == -1) {
					return stream.toByteArray();
				}
				byte b = buffer[0];
				if(b == '\n') {
					break;
				}
				if(b == '\r') {
					if(System.lineSeparator().equals("\r\n")) {
						System.in.read(buffer);
					}
					break;
				}
				stream.write(buffer);
			}
			return stream.toByteArray();
		}
	}
	
	/**
	 * Checks that the console is secure for password input
	 */
	private static void checkConsole() {
		if(Configuration.isForceSafeConsole() && (!Configuration.isSafeConsole() || System.console() == null)) {
			System.out.println("The console is not safe for password input, aborting");
			System.exit(0);
		}
	}
}