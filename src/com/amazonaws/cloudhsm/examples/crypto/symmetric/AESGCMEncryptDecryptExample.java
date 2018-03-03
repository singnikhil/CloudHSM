package com.amazonaws.cloudhsm.examples.crypto.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.GCMParameterSpec;

import com.amazonaws.cloudhsm.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumAESKey;

public class AESGCMEncryptDecryptExample {

	String plainText = "This!";
	String aad = "aad";
	String transformation = "AES/GCM/NoPadding";
	
	int tagLengthInBytes = 16;
	int ivSizeReturnedByHSM;
	public static void main(String[] z) {

		AESGCMEncryptDecryptExample obj = new AESGCMEncryptDecryptExample();
		//Logging in to HSM with CU user
		LoginLogoutExample.loginWithExplicitCredentials();
		//Generating a new AES Key for encryption
		Key key =new AESSymmetricKeyGeneration().generateAESKey(256, true);
		byte[] iv = null;

		System.out.println("Performing AES Encryption Operation");
		byte[] result = obj.encrypt(obj.transformation, (CaviumAESKey) key, obj.plainText, obj.aad, obj.tagLengthInBytes);
		System.out.println("Plaintext Encrypted");

		System.out.println("Base64 Encoded Encrypted Text with IV = " + Base64.getEncoder().encodeToString(result));

		System.out.println("Perfroming Decrypt Operation");
		
		//Extracting IV for Decrypt operation
		iv = Arrays.copyOfRange(result, 0, obj.ivSizeReturnedByHSM);

		byte[] cipherText = Arrays.copyOfRange(result, obj.ivSizeReturnedByHSM, result.length);
		System.out.println("Base64 Encoded Cipher Text = " + Base64.getEncoder().encodeToString(cipherText));

		byte[] decryptedText = obj.decrypt(obj.transformation, (CaviumAESKey) key, cipherText, iv, obj.aad, obj.tagLengthInBytes);
		System.out.println("Plain Text = "+new String(decryptedText));
		LoginLogoutExample.logout();
	}

	public byte[] encrypt(String transformation, CaviumAESKey key, String plainText, String aad, int tagLength) {
		try {
			Cipher encCipher = Cipher.getInstance(transformation, "Cavium");

			encCipher.init(Cipher.ENCRYPT_MODE, key);
			encCipher.updateAAD(aad.getBytes());
			encCipher.update(plainText.getBytes());
			byte[] ciphertext = encCipher.doFinal();

			//You'll get a new IV from HSM after encryption. Save it, as you'll need them to recreate GCMParameterSpec for Decrypt operation. 
			//IV has a fixed length 16 bytes. Appending IV to CipherText for easier management. 
			ivSizeReturnedByHSM = encCipher.getIV().length;
			byte[] finalResult = new byte[ivSizeReturnedByHSM + ciphertext.length]; 
			System.arraycopy(encCipher.getIV(), 0, finalResult, 0, ivSizeReturnedByHSM);
            System.arraycopy(ciphertext, 0, finalResult, ivSizeReturnedByHSM, ciphertext.length);
			return finalResult;

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		//} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			//e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public byte[] decrypt(String transformation, CaviumAESKey key, byte[] cipherText , byte[] iv, String aad, int tagLength) {
		Cipher decCipher;
		try {
			decCipher = Cipher.getInstance(transformation, "Cavium");
			GCMParameterSpec gcmSpec = new GCMParameterSpec(tagLengthInBytes * Byte.SIZE,iv);
			decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
			decCipher.updateAAD(aad.getBytes());
			return decCipher.doFinal(cipherText);

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}