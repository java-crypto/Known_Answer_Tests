package Block_Cipher.AES.GCM_SIV;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

public class EasyAES {
	private static byte[] key; // Should be 16 or 32 Bytes
	private static byte[] nonce; // Should be 12 Bytes (96 Bits)
	private static byte[] cdata; // Not limited
	private static AEAD aead;
	
	public EasyAES(byte[] key, byte[] nonce, byte[] cdata) {
		EasyAES.key = key;
		EasyAES.nonce = nonce;
		EasyAES.cdata = cdata;
		if (!corKeySize(key)) {
			System.err.println("[EasyAES] Key should be 16 or 32 Bytes (128 Bits or 256 Bits) long!" );
			System.err.println("[EasyAES] Please reset your key");
		} else {
			EasyAES.aead = new AEAD(key);
		}
		if (nonce.length != 12) {
			System.err.println("[EasyAES] Nonce should be 12 Bytes (96 Bits) long!");
			System.err.println("[EasyAES] Please reset your nonce");
		}
	}
	
	public EasyAES(byte[] key, byte[] nonce) {
		EasyAES.key = key;
		EasyAES.nonce = nonce;
		if (!corKeySize(key)) {
			System.err.println("[EasyAES] Key should be 16 or 32 Bytes (128 Bits or 256 Bits) long!" );
			System.err.println("[EasyAES] Please reset your key");
		} else {
			EasyAES.aead = new AEAD(key);
		}
		if (nonce.length != 12) {
			System.err.println("[EasyAES] Nonce should be 12 Bytes (96 Bits) long!");
			System.err.println("[EasyAES] Please reset your nonce");
		}
		System.out.println("[EasyAES] Please be advised: Without credential data, SIV can not function properly.");
	}
	
	public EasyAES() {
		System.out.println("[EasyAES] Please be advised: Without initializing param, you need to specified the param manually");
	}
	
	public EasyAES(int keySize) {
		SecureRandom sr = new SecureRandom();
		if (keySize == 128) {
			key = new byte[16];
			nonce = new byte[12];
			cdata = new byte[16];
			sr.nextBytes(key);
			sr.nextBytes(nonce);
			sr.nextBytes(cdata);
			EasyAES.aead = new AEAD(key);
			System.out.println("[EasyAES] Generating parameters for 128 Bit AES Automatically");
		} else if (keySize == 256) {
			key = new byte[32];
			nonce = new byte[12];
			cdata = new byte[32];
			sr.nextBytes(key);
			sr.nextBytes(nonce);
			sr.nextBytes(cdata);
			EasyAES.aead = new AEAD(key);
			System.out.println("[EasyAES] Generating parameters for 256 Bit AES Automatically");
		} else {
			System.err.println("[EasyAES] Bad keySize specified!");
			System.err.println("[EasyAES] Please reset keySize Param");
		}
	}
	
	public byte[] getKey() {
		if (key == null) {
			System.err.println("[EasyAES] No key specified!");
			return null;
		} else {
			return key;
		}
	}
	
	public void setKey(byte[] key) {
		if (key == null) {
			System.err.println("[EasyAES] No key specified!");
		} else if (!corKeySize(key)) {
			System.err.println("[EasyAES] Bad keySize specified!");
			System.err.println("[EasyAES] The key should be 16 or 32 Bytes (128 bits or 256 bits) long");
		} else {
			EasyAES.aead = new AEAD(key);
			EasyAES.key = key;
			
		}
	}
	
	public void setNonce(byte[] nonce) {
		if (nonce == null) {
			System.err.println("[EasyAES] No nonce specified!");
		} else if (nonce.length != 12) {
			System.err.println("[EasyAES] Bad nonceSize specified!");
			System.err.println("[EasyAES] The nonce should be 12 Bytes (96 bits) long");			
		} else {
			EasyAES.nonce = nonce;
		}
	}
	
	public void setCdata(byte[] cdata) {
		if (cdata == null) {
			System.err.println("[EasyAES] No credential data specified!");
		} else {
			EasyAES.cdata = cdata;
		}
	}
	
	public byte[] getNonce() {
		if (nonce == null) {
			System.err.println("[EasyAES] No nonce specified!");
			return null;
		} else {
			return nonce;
		}
	}
	
	public byte[] getCdata() {
		if (cdata == null) {
			System.err.println("[EasyAES] No credential data specified!");
			return null;
		} else {
			return cdata;
		}
	}
	
	public byte[] SIV_encrypt(byte[] data) {
		if (data == null) {
			System.err.println("[EasyAES] No input data for SIV_encrypt, nothing to do.");
			return null;
		}
		if (checkParam() == 2) {
			return aead.seal(nonce, data, cdata);
		} else {
			return null;
		}
	}
	
	public byte[] SIV_decrypt(byte[] sivCipher) {
		if (sivCipher == null) {
			System.err.println("[EasyAES] No input data for SIV_Decrypt, nothing to do.");
			return null;
		}
		if (checkParam() == 2) {
			return aead.open(nonce,  sivCipher, cdata).get();
		} else {
			return null;
		}
		
	}
	
	public byte[] GCM_encrypt(byte[] data) throws Exception {
		if (data == null) {
			System.err.println("[EasyAES] No input data for GCM_encrypt, nothing to do.");
			return null;
		}
		if (checkParam() >= 1) {
			final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			final GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
			final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);
			return cipher.doFinal(data);
		} else {
			return null;
		}
	}
	
	public byte[] GCM_decrypt(byte[] gcmCipher) throws Exception {
		if (gcmCipher == null) {
			System.err.println("[EasyAES] No input data for GCM decrypt, nothing to do.");
			return null;
		}
		if (checkParam() >= 1) {
			final Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
			final GCMParameterSpec gcmSpec = new GCMParameterSpec(128, nonce);
			final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
			cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);
			return cipher.doFinal(gcmCipher);
		} else {
			return null;
		}
		
	}
	
	private int checkParam() {
		int result = 0;
		if (key == null) {
			System.err.println("[EasyAES] No key specified!");
			return result;
		} else {
			if (!corKeySize(key)) {
				System.err.println("Bad keySize specified!");
				System.err.println("The key should be 16 or 32 Bytes (128 bits or 256 bits) long");
				return result;
			}
		}
		
		if (nonce == null) {
			System.err.println("[EasyAES] No nonce specified!");
			return result;
		} else {
			if (nonce.length != 12) {
				System.err.println("[EasyAES] Bad nonceSize specified!");
				System.err.println("[EasyAES] The nonce should be 12 Bytes (96 bits) long");
				return result;
			}
			else {
				result++;
			}
		}
		
		if (cdata == null) {
			System.err.println("[EasyAES] No Credential data specified!");
			System.err.println("[EasyAES] SIV function disabled. Please consider using GCM");
		} else {
			result++;
		}
		return result;
		
		// result = 0, insufficient for both SIV and GCM
		// result = 1, sufficient for GCM
		// result = 2, sufficient for both SIV and GCM
	}
	
	private boolean corKeySize(byte[] key) {
		if (key.length == 16 || key.length == 32) {
			return true;
		} else {
			return false;
		}
	}

}
