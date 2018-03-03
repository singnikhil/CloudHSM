package com.amazonaws.cloudhsm.classic.examples.crypto.symmetric;

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

import com.amazonaws.cloudhsm.classic.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.classic.examples.operations.LoginLogoutExample;
import com.safenetinc.luna.provider.key.LunaSecretKey;
import com.safenetinc.luna.provider.param.LunaGcmParameterSpec;

public class AESEncryptDecryptExample {

	public String plainText = "This is a sample plaintext!";
	public String aad = "aad";
	public String transformation = "AES/GCM/NoPadding";
	public int ivSizeInBytes=12;
	public int tagLengthInBytes = 16;
	public int ivSizeReturnedByHSM;
	public static void main(String[] z) {

		LoginLogoutExample.loginToPartition("haGroup", "passw0rd@123");
		
		AESEncryptDecryptExample obj = new AESEncryptDecryptExample();
		Key key =new AESSymmetricKeyGeneration().generateAESKey(192, "Enc/Dec-2", true, true);
		byte[] iv = obj.generateIV(obj.ivSizeInBytes);

		System.out.println("Performing AES Encryption Operation");
		byte[] result = obj.encrypt(obj.transformation, (LunaSecretKey) key, obj.plainText, iv, obj.aad, obj.tagLengthInBytes);
		System.out.println("Plaintext Encrypted");
		System.out.println("Base64 Encoded Encrypted Text = " + Base64.getEncoder().encodeToString(result));
		System.out.println("Perfroming Decrypt Operation");
		//Extracting IV for Decrypt operation
		iv = Arrays.copyOfRange(result, 0, obj.ivSizeReturnedByHSM);
		byte[] cipherText = Arrays.copyOfRange(result, obj.ivSizeReturnedByHSM, result.length);

		byte[] decryptedText = obj.decrypt(obj.transformation, (LunaSecretKey) key, cipherText, iv, obj.aad, obj.tagLengthInBytes);
		System.out.println("Plain Text = "+new String(decryptedText));
		LoginLogoutExample.logout();
	}

	public byte[] encrypt(String transformation, LunaSecretKey key, String plainText, byte[] iv, String aad, int tagLength) {
		try {
			Cipher encCipher = Cipher.getInstance(transformation, "LunaProvider");
			LunaGcmParameterSpec gcmSpec = new LunaGcmParameterSpec(iv,aad.getBytes(), tagLengthInBytes * 8);
			encCipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
			//encCipher.updateAAD(aad.getBytes());
			encCipher.update(plainText.getBytes());
			byte[] ciphertext = encCipher.doFinal();
			
			//You'll get a new IV from HSM after encryption. Save it, as you'll need them to recreate GCMParameterSpec for Decrypt operation. 
			//IV has a fixed length 16 bytes. Appending IV to CipherText for easier management. 
			ivSizeReturnedByHSM = gcmSpec.getIv().length;
			byte[] finalResult = new byte[ivSizeReturnedByHSM + ciphertext.length]; 
			System.arraycopy(gcmSpec.getIv(), 0, finalResult, 0, ivSizeReturnedByHSM);
            System.arraycopy(ciphertext, 0, finalResult, ivSizeReturnedByHSM, ciphertext.length);
			return finalResult;

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
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
	
	public byte[] generateIV(int ivSizeinByets) {
		SecureRandom sr;
		try {
			sr = SecureRandom.getInstance("LunaRNG", "LunaProvider");
			byte[] iv = new byte[ivSizeinByets];
			sr.nextBytes(iv);  
			return iv;
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
	

	public byte[] decrypt(String transformation, LunaSecretKey key, byte[] cipherText , byte[] iv, String aad, int tagLength) {
		Cipher decCipher;
		try {
			decCipher = Cipher.getInstance(transformation, "LunaProvider");
			LunaGcmParameterSpec gcmSpec = new LunaGcmParameterSpec(iv,aad.getBytes(), tagLengthInBytes * 8);
			decCipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
			//decCipher.updateAAD(aad.getBytes());
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