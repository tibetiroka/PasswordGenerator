package tibetiroka.pwgen;

import lombok.NonNull;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * Provides utilities for arrays. Mainly contains rewrites of standard List functions for byte arrays.
 */
public class ArrayUtils {
	/**
	 * Shuffles the specified byte array using the provided secure random number generator.
	 *
	 * @param array  The array to shuffle
	 * @param random The random generator
	 */
	public static void shuffle(@NonNull byte[] array, @NonNull SecureRandom random) {
		for(int current = 0; current < array.length; current++) {
			int other = random.nextInt(array.length);
			swap(array, current, other);
		}
		for(int i = 0; i < Math.min(array.length * 100, array.length * array.length); i++) {
			swap(array, random.nextInt(array.length), random.nextInt(array.length));
		}
	}
	
	/**
	 * Swaps two bytes in the array.
	 *
	 * @param array  The array of bytes
	 * @param first  The index of the first byte
	 * @param second The index of the second byte
	 */
	public static void swap(@NonNull byte[] array, int first, int second) {
		byte temp = array[first];
		array[first] = array[second];
		array[second] = temp;
	}
	
	/**
	 * Creates a string representation of the specified array using base64 encoding
	 *
	 * @param array The byte array
	 * @return The base64 string
	 */
	public static @NonNull String toBase64String(@NonNull byte[] array) {
		return new String(Base64.getEncoder().encode(array), StandardCharsets.US_ASCII);
	}
	
	/**
	 * Encodes the specified array using base64.
	 *
	 * @param array The array to encode
	 * @return The encoded array
	 */
	public static @NonNull byte[] toBase64(@NonNull byte[] array) {
		return Base64.getEncoder().encode(array);
	}
	
	/**
	 * Creates a byte array out of the specified char array assuming it uses UTF-8 encoding.
	 *
	 * @param array The char array
	 * @return The byte array
	 */
	public static @NonNull byte[] toByteArray(@NonNull char[] array) {
		CharBuffer charBuffer = CharBuffer.wrap(array);
		ByteBuffer byteBuffer = StandardCharsets.UTF_8.encode(charBuffer);
		byte[] bytes = Arrays.copyOfRange(byteBuffer.array(), byteBuffer.position(), byteBuffer.limit());
		Arrays.fill(byteBuffer.array(), (byte) 0);
		return bytes;
	}
	
	/**
	 * Creates a char array out of hte specified byte array assuming it uses US_ASCII encoding.
	 *
	 * @param array The byte array
	 * @return The char array
	 */
	public static @NonNull char[] toCharArray(@NonNull byte[] array) {
		ByteBuffer byteBuffer = ByteBuffer.wrap(array);
		CharBuffer charBuffer = StandardCharsets.US_ASCII.decode(byteBuffer);
		char[] chars = Arrays.copyOfRange(charBuffer.array(), charBuffer.position(), charBuffer.limit());
		Arrays.fill(charBuffer.array(), (char) 0);
		return chars;
	}
}
