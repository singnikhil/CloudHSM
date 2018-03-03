package com.amazonaws.cloudhsm.examples.crypto.symmetric;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

import com.amazonaws.cloudhsm.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumAESKey;

public class AESWrapUnwrapExample {

	String plainText = "This!";
	String aad = "aad";
	String transformation = "AES/CBC/PKCS5Padding";
	int ivSizeInBytes=16;
	int tagLengthInBytes = 16;
	int ivSizeReturnedByHSM;
	public static void main(String[] z) throws NoSuchAlgorithmException, NoSuchProviderException {

		System.out.println("I Rule!");
		System.out.println(Cipher.SECRET_KEY);
		AESWrapUnwrapExample obj = new AESWrapUnwrapExample();
		LoginLogoutExample.loginWithExplicitCredentials();
		//Generate Wrapping Key
		CaviumAESKey wrappingKey =(CaviumAESKey)new AESSymmetricKeyGeneration().generateAESKey(256, true);
		byte[] iv = obj.generateIV(obj.ivSizeInBytes);

		//Generate Key To Be wrapped. This is a Software Key
		//KeyGenerator generator = KeyGenerator.getInstance("AES", "SunJCE");
        //generator.init(256);
        //Key keyToBeWrapped = generator.generateKey();
		
		
		//Generate Key To Be wrapped. This is a Cavium Key
        Key keyToBeWrapped =(CaviumAESKey)new AESSymmetricKeyGeneration().generateAESKey(256, true);
        
        //Printing encoded bits of keyToBeWrapped
		System.out.println("Base64 Encoded key to be wrapped = " + Base64.getEncoder().encodeToString(keyToBeWrapped.getEncoded()));

		System.out.println("Performing AES Wrapping");
		byte[] result = obj.wrap(obj.transformation, wrappingKey, keyToBeWrapped, iv);
		
		System.out.println("Key Wrapped");
		System.out.println("Base64 Encoded wrapped key = " + Base64.getEncoder().encodeToString(result));

		System.out.println("Perfroming Key Unwrapping");
		//Extracting IV for Unwrapping operation
		iv = Arrays.copyOfRange(result, 0, obj.ivSizeReturnedByHSM);
		
		byte[] wrappedKey = Arrays.copyOfRange(result, obj.ivSizeReturnedByHSM, result.length);

		Key unwrappedKey = obj.unWrap(obj.transformation, wrappingKey, wrappedKey, keyToBeWrapped.getAlgorithm(), iv);
		
		//Printing encoded bits of unwrapped key. If these bits match, then the key originally wrapped was unwrapped successfully.  
		System.out.println("Base64 Encoded unwrapped key= " + Base64.getEncoder().encodeToString(unwrappedKey.getEncoded()));

		LoginLogoutExample.logout();
	}

	public Key unWrap(String transformation, CaviumAESKey wrappingKey, byte[] wrappedKey, String keyAlgo, byte[] iv) {
		try {
			Cipher wrapCipher = Cipher.getInstance(transformation, "Cavium");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			wrapCipher.init(Cipher.UNWRAP_MODE, wrappingKey, ivSpec);

			Key upWrappedKey = wrapCipher.unwrap(wrappedKey, keyAlgo, Cipher.SECRET_KEY);

			return upWrappedKey;

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
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

	public byte[] wrap(String transformation, CaviumAESKey wrappingKey, Key keyToBeWrapped, byte[] iv) {
		try {
			Cipher wrapCipher = Cipher.getInstance(transformation, "Cavium");
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			wrapCipher.init(Cipher.WRAP_MODE, wrappingKey, ivSpec);
			byte[] wrappedKey = wrapCipher.wrap(keyToBeWrapped);

			ivSizeReturnedByHSM = wrapCipher.getIV().length;
			byte[] finalResult = new byte[ivSizeReturnedByHSM + wrappedKey.length]; 
			System.arraycopy(wrapCipher.getIV(), 0, finalResult, 0, ivSizeReturnedByHSM);
            System.arraycopy(wrappedKey, 0, finalResult, ivSizeReturnedByHSM, wrappedKey.length);
			return finalResult;

		} catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		} 
		return null;
	}

}