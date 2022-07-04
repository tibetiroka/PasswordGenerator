package tibetiroka.pwgen.version;

import lombok.NonNull;
import tibetiroka.pwgen.PasswordGenerator;

import java.lang.reflect.InvocationTargetException;

/**
 * Handles the usage of different password generators. Supports adding custom version during runtime.
 */
public class VersionManager {
	/**
	 * Gets a generator for the specified version. If the version is null or a generator cannot be created, returns null.
	 *
	 * @param version The version of generator to create
	 * @return The generator or null
	 */
	public static PasswordGenerator getGenerator(GeneratorVersion version) {
		if(version == null) {
			return null;
		}
		try {
			return version.getNewInstance();
		} catch(Exception e) {
			return null;
		}
	}
	
	/**
	 * Gets a generator for the specified version. If the version is null, there is no version registered with the specified name (case-insensitive) or there is no class in this package with the specified name ("PasswordGenerator_VERSION"), returns null.
	 *
	 * @param version The name of the version of generator
	 * @return The generator or null
	 */
	public static PasswordGenerator getGenerator(String version) {
		if(version == null) {
			return null;
		}
		try {
			try {
				GeneratorVersion v = GeneratorVersion.valueOf(version.toUpperCase());
				return getGenerator(v);
			} catch(Exception e) {
				return (PasswordGenerator) Class.forName(VersionManager.class.getPackageName() + ".PasswordGenerator_" + version.toUpperCase()).getDeclaredConstructor().newInstance();
			}
		} catch(Throwable e) {
			return null;
		}
	}
	
	/**
	 * Enum storing the provided generator versions
	 */
	public enum GeneratorVersion {
		ALEPH(PasswordGenerator_ALEPH.class);
		/**
		 * The class of the specified generator version
		 */
		private final @NonNull Class<? extends PasswordGenerator> genClass;
		
		GeneratorVersion(@NonNull Class<? extends PasswordGenerator> c) {
			this.genClass = c;
		}
		
		/**
		 * Gets a new instance of the password generator.
		 *
		 * @return The generator
		 * @throws NoSuchMethodException     if there is no default constructor defined
		 * @throws IllegalAccessException    if the default constructor is not accessible
		 * @throws InvocationTargetException if the underlying constructor throws an exception
		 * @throws InstantiationException    if the constructor throws an exception
		 */
		public @NonNull PasswordGenerator getNewInstance() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
			return genClass.getDeclaredConstructor().newInstance();
		}
	}
}
