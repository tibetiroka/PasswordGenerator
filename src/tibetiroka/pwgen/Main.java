package tibetiroka.pwgen;

import tibetiroka.pwgen.version.VersionManager;

import java.util.Scanner;

public class Main {
	
	public static void main(String[] args) {
		Scanner sc = new Scanner(System.in);
		System.out.println("Password Generator");
		System.out.println("Please name the version you want to use (leave blank for latest version)");
		PasswordGenerator gen = null;
		do {
			String version = sc.nextLine();
			if(version.trim().isEmpty()) {
				version = VersionManager.GeneratorVersion.values()[VersionManager.GeneratorVersion.values().length - 1].name();
			}
			gen = VersionManager.getGenerator(version);
			if(gen == null) {
				System.out.println("Unknown version");
			}
		} while(gen == null);
		System.out.println("Please name the site or application:");
		String site = sc.nextLine().toLowerCase();
		System.out.println("Please name your preferred username:");
		String username = sc.nextLine();
		System.out.println("Please type in your personal secret code:");
		String secret = sc.nextLine();
		String pw = null;
		try {
			pw = gen.generate(secret, site, username);
		} catch(Exception e) {
			System.out.println("Could not generate password");
			e.printStackTrace();
			System.exit(-1);
		}
		System.out.println("Your password is:");
		System.out.println(pw);
	}
	
	
}
