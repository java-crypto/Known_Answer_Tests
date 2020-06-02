package Block_Cipher.AES.GCM_SIV;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Optional;

public class AEAD {
	
	static final int AES_BLOCK_SIZE = 16;
	private static final int NONCE_SIZE = 12;
	private final Cipher aes;
	private final SecureRandom random;
	private final boolean aes128;
	
	public AEAD(byte[] key) {
		if (key.length != 16 && key.length != 32) {
			throw new IllegalArgumentException("Key must be 16 or 32 bytes long");
		}
		
		this.aes = newAES(key);
		this.random = new SecureRandom();
		this.aes128 = key.length == 16;
	}

	public byte[] seal(byte[] nonce, byte[] plaintext, byte[] data) {
		if (nonce.length != NONCE_SIZE) {
			throw new IllegalArgumentException("Nonce must be 12 bytes long");
		}
		final byte[] authKey = subKey(0, 1, nonce);
		final Cipher encAES = newAES(subKey(2, aes128 ? 3 : 5, nonce));
		final byte[] tag = hash(encAES, authKey, nonce, plaintext, data);
		final byte[] output = new byte[plaintext.length + tag.length];
		aesCTR(encAES, tag, plaintext, output);
		System.arraycopy(tag, 0, output, plaintext.length, tag.length);
		return output;
	}

	public byte[] seal(byte[] plaintext, byte[] data) {
		final byte[] nonce = new byte[NONCE_SIZE];
		random.nextBytes(nonce);
		
		final byte[] ciphertext = seal(nonce, plaintext, data);
		final byte[] output = new byte[nonce.length + ciphertext.length];
		System.arraycopy(nonce, 0, output, 0, nonce.length);
		System.arraycopy(ciphertext, 0, output, nonce.length, ciphertext.length);
		return output;
	}

	public Optional<byte[]> open(byte[] nonce, byte[] ciphertext, byte[] data) { //Template Types
		if (nonce.length != NONCE_SIZE) {
			throw new IllegalArgumentException("Nonce must be 12 bytes long");
		}
		final byte[] c = new byte[ciphertext.length - AES_BLOCK_SIZE];
		final byte[] tag = new byte[AES_BLOCK_SIZE];
		System.arraycopy(ciphertext, 0, c, 0, c.length);
		System.arraycopy(ciphertext, c.length, tag, 0, tag.length);
		final byte[] authKey = subKey(0, 1, nonce);
		final Cipher encAES = newAES(subKey(2, aes128 ? 3 : 5, nonce));
		aesCTR(encAES, tag, c, c);
		final byte[] actual = hash(encAES, authKey, nonce, c, data);
		if (MessageDigest.isEqual(tag, actual)) {
			return Optional.of(c);
		}
		return Optional.empty();
	}

	public Optional<byte[]> open(byte[] ciphertext, byte[] data) {
		if (ciphertext.length < NONCE_SIZE) {
			return Optional.empty();
		}
		final byte[] nonce = new byte[NONCE_SIZE];
		final byte[] c = new byte[ciphertext.length - NONCE_SIZE];
		System.arraycopy(ciphertext, 0, nonce, 0, nonce.length);
		System.arraycopy(ciphertext, nonce.length, c, 0, c.length);
		
		return open(nonce, c, data);
	}

	private byte[] hash(Cipher aes, byte[] h, byte[] nonce, byte[] plaintext, byte[] data) {
		final Polyval polyval = new Polyval(h);
		polyval.update(data); // hash data with padding
		polyval.update(plaintext); // hash plaintext with padding

		// hash data and plaintext lengths in bits with padding
		final byte[] block = new byte[AES_BLOCK_SIZE];
		Bytes.putLong((long) data.length * 8, block, 0);
		Bytes.putLong((long) plaintext.length * 8, block, 8);
		polyval.updateBlock(block, 0);
		polyval.digest(block);
		for (int i = 0; i < nonce.length; i++) {
			block[i] ^= nonce[i];
		}
		block[block.length - 1] &= (byte) ~0x80;
		// encrypt polyval hash to produce tag
		try {
			aes.update(block, 0, block.length, block, 0);
		} catch (ShortBufferException e) {
			throw new IllegalStateException(e);
		}
		return block;
	}
	
	private byte[] subKey(int ctrStart, int ctrEnd, byte[] nonce) {
		final byte[] counter = new byte[AES_BLOCK_SIZE];
		System.arraycopy(nonce, 0, counter, counter.length - nonce.length, nonce.length);
		final byte[] key = new byte[(ctrEnd - ctrStart + 1) * 8];
		final byte[] block = new byte[AES_BLOCK_SIZE];
		for (int i = ctrStart; i <= ctrEnd; i++) {
			Bytes.putInt(i, counter);
			try {
				aes.update(counter, 0, AES_BLOCK_SIZE, block, 0);
			} catch (ShortBufferException e) {
				throw new IllegalStateException(e);
			}
			System.arraycopy(block, 0, key, (i - ctrStart) * 8, 8);
		}
		return key;
	}
	
	private void aesCTR(Cipher aes, byte[] tag, byte[] input, byte[] output) {
		final byte[] counter = Arrays.copyOf(tag, tag.length);
		counter[counter.length - 1] |= (byte) 0x80;
		final byte[] k = new byte[AES_BLOCK_SIZE];
		for (int i = 0; i < input.length; i += AES_BLOCK_SIZE) {
			// encrypt counter to produce keystream
			try {
				aes.update(counter, 0, counter.length, k, 0);
			} catch (ShortBufferException e) {
				throw new IllegalStateException(e);
			}
			
			// xor input with keystream
			final int len = Math.min(AES_BLOCK_SIZE, input.length - i);
			for (int j = 0; j < len; j++) {
				final int idx = i + j;
				output[idx] = (byte) (input[idx] ^ k[j]);
			}
			
			// increment counter
			int j = 0;
			while (j < 4 && ++counter[j] == 0) {
				j++;
			}
		}
	}
	
	private Cipher newAES(byte[] key) {
		try {
			final Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
			return cipher;
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException e) {
			throw new IllegalStateException(e);
		}
	}
}