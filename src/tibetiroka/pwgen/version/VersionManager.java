package tibetiroka.pwgen.version;

import tibetiroka.pwgen.PasswordGenerator;

import java.lang.reflect.InvocationTargetException;

public class VersionManager {
	public static PasswordGenerator getGenerator(GeneratorVersion version) {
		try {
			return version.getNewInstance();
		} catch(Exception e) {
			return null;
		}
	}
	
	public static PasswordGenerator getGenerator(String version) {
		try {
			try {
				GeneratorVersion v = GeneratorVersion.valueOf(version.toUpperCase());
				return getGenerator(v);
			} catch(Exception e) {
			}
			return (PasswordGenerator) Class.forName(VersionManager.class.getPackageName() + ".PasswordGenerator_" + version.toUpperCase()).getDeclaredConstructor().newInstance();
		} catch(Throwable e) {
			return null;
		}
	}
	
	public enum GeneratorVersion {
		ALPHA(PasswordGenerator_ALPHA.class), BETA(PasswordGenerator_BETA.class);
		private final Class<? extends PasswordGenerator> genClass;
		
		GeneratorVersion(Class<? extends PasswordGenerator> c) {
			this.genClass = c;
		}
		
		public PasswordGenerator getNewInstance() throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
			return genClass.getDeclaredConstructor().newInstance();
		}
	}
}
