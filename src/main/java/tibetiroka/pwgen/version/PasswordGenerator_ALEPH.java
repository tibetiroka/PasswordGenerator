package tibetiroka.pwgen.version;

import lombok.NonNull;
import tibetiroka.pwgen.ArrayUtils;
import tibetiroka.pwgen.PasswordGenerator;

public class PasswordGenerator_ALEPH extends PasswordGenerator {
	@Override
	public @NonNull byte[] generate(@NonNull byte[] password, @NonNull byte[] site, @NonNull byte[] username) throws Exception {
		password = secureRandomBytes(password, 256);
		site = secureRandomBytes(site, 256);
		username = secureRandomBytes(username, 256);
		byte[] temp = createSaltedKey(username, createSaltedKey(site, password));
		temp = createSaltedKey(username, encryptAES(username, secureRandomBytes(temp, 32)));
		temp = hash(temp, xorPad(password, username));
		temp = ArrayUtils.toBase64(temp);
		byte[] result = new byte[32];
		System.arraycopy(temp, 0, result, 0, result.length);
		return result;
	}
}
