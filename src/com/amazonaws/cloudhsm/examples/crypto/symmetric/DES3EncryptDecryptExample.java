package com.amazonaws.cloudhsm.examples.crypto.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.amazonaws.cloudhsm.examples.key.symmetric.DES3SymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumDES3Key;

public class DES3EncryptDecryptExample {

	String plainText = "This is a sample Plain Text Message!";
	String transformation = "DESede/CBC/NoPadding";//DESede/CBC/PKCS5Padding
	int ivSizeInBytes=8;

	public static void main(String[] z) {

		DES3EncryptDecryptExample obj = new DES3EncryptDecryptExample();
		LoginLogoutExample.loginWithExplicitCredentials();
		Key key =new DES3SymmetricKeyGeneration().generate3DesKey(192, true);
		byte[] iv = obj.generateIV(obj.ivSizeInBytes);

		System.out.println("Performing DES3 Encryption Operation");
		byte[] result = obj.encrypt(obj.transformation, (CaviumDES3Key) key, obj.plainText, iv);
		System.out.println("Plaintext Encrypted");
		System.out.println("Base64 Encoded Encrypted Text = " + Base64.getEncoder().encodeToString(result));
		System.out.println("Perfroming Decrypt Operation");
		//Extracting IV for Decrypt operation
		iv = Arrays.copyOfRange(result, 0, obj.ivSizeInBytes);
		byte[] cipherText = Arrays.copyOfRange(result, obj.ivSizeInBytes, result.length);

		byte[] decryptedText = obj.decrypt(obj.transformation, (CaviumDES3Key) key, cipherText, iv);
		System.out.println("Plain Text = "+new String(decryptedText));
		LoginLogoutExample.logout();
	}

	public byte[] encrypt(String transformation, CaviumDES3Key key, String plainText, byte[] iv) {
		try {
			Cipher encCipher = Cipher.getInstance(transformation, "Cavium");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			encCipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
			encCipher.update(plainText.getBytes());
			byte[] ciphertext = encCipher.doFinal();
			//You'll get a new IV from HSM after encryption. Save it, as you'll need them to recreate IvParameterSpec for Decrypt operation. 
			//IV has a fixed length 16 bytes. Appending IV to CipherText for easier management. 
			byte[] finalResult = new byte[encCipher.getIV().length + ciphertext.length]; 
			System.arraycopy(encCipher.getIV(), 0, finalResult, 0, encCipher.getIV().length);
            System.arraycopy(ciphertext, 0, finalResult, encCipher.getIV().length, ciphertext.length);
			return finalResult;

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public byte[] generateIV(int ivSizeinByets) {
		SecureRandom sr;
		try {
			sr = SecureRandom.getInstance("AES-CTR-DRBG", "Cavium");
			byte[] iv = new byte[ivSizeinByets];
			sr.nextBytes(iv);  
			return iv;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}
	
	public byte[] decrypt(String transformation, CaviumDES3Key key, byte[] cipherText, byte[] iv) {
		Cipher decCipher;
		try {
			decCipher = Cipher.getInstance(transformation, "Cavium");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			decCipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
			return decCipher.doFinal(cipherText);
		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}