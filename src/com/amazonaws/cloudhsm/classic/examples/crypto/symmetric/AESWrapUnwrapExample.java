package com.amazonaws.cloudhsm.classic.examples.crypto.symmetric;

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

import com.amazonaws.cloudhsm.classic.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.classic.examples.operations.LoginLogoutExample;
import com.safenetinc.luna.provider.key.LunaSecretKey;

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
		LoginLogoutExample.loginToPartition("haGroup", "passw0rd@123");
		//Generate Wrapping Key
		LunaSecretKey wrappingKey =(LunaSecretKey)new AESSymmetricKeyGeneration().generateAESKey(128, "AES-WrappingKey", true, true);
		byte[] iv = obj.generateIV(obj.ivSizeInBytes);


		LunaSecretKey keyToBeWrapped =(LunaSecretKey)new AESSymmetricKeyGeneration().generateAESKey(128, "AES-WrapKeyTest", true, true);
        
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

	public Key unWrap(String transformation, LunaSecretKey wrappingKey, byte[] wrappedKey, String keyAlgo, byte[] iv) {
		try {
			Cipher wrapCipher = Cipher.getInstance(transformation, "LunaProvider");
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

	public byte[] wrap(String transformation, LunaSecretKey wrappingKey, Key keyToBeWrapped, byte[] iv) {
		try {
			Cipher wrapCipher = Cipher.getInstance(transformation, "LunaProvider");
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