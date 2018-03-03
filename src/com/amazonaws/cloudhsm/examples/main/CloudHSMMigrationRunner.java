package com.amazonaws.cloudhsm.examples.main;

import java.security.Key;
import java.util.Arrays;

import com.amazonaws.cloudhsm.classic.examples.crypto.symmetric.AESEncryptDecryptExample;
import com.amazonaws.cloudhsm.classic.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.classic.examples.operations.LoginLogoutExample;
import com.amazonaws.cloudhsm.examples.operations.KeyManagement;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumKey;
import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.key.LunaSecretKey;

public class CloudHSMMigrationRunner {

	public String plainText = "This is a sample plaintext!";
	public String aad = "aad";
	public String transformation = "AES/GCM/NoPadding";
	public int ivSizeInBytes=12;
	public int tagLengthInBytes = 16;
	
	
	public static void main(String[] args) {
		
		CloudHSMMigrationRunner migrationRunnerObject = new CloudHSMMigrationRunner();
		System.out.println("I Rule!");
		LoginLogoutExample.loginToPartition("haGroup", "passw0rd@123");
	//	Key key = new AESSymmetricKeyGeneration().generateAESKey(128, "AES-MigrationTest", true, true);
		AESEncryptDecryptExample obj = new AESEncryptDecryptExample();
		
		LunaSecretKey key = new LunaSecretKey(LunaTokenObject.LocateObjectByAlias("NewKey1")) ;
		byte[] iv = obj.generateIV(migrationRunnerObject.ivSizeInBytes);
		System.out.println("Performing AES Encryption Operation");
		byte[] result = obj.encrypt(migrationRunnerObject.transformation, (LunaSecretKey) key, migrationRunnerObject.plainText, iv, migrationRunnerObject.aad, migrationRunnerObject.tagLengthInBytes);
		System.out.println("Plaintext Encrypted");
		
		com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample.loginWithExplicitCredentials();
		//long handle = KeyManagement.importKey(key, "AES-MigrationTest", true, true);
		CaviumKey ck = KeyManagement.getKey(265400);
		
		iv = Arrays.copyOfRange(result, 0, obj.ivSizeReturnedByHSM);
		byte[] cipherText = Arrays.copyOfRange(result, obj.ivSizeReturnedByHSM, result.length);
		
		byte[] decryptedText = new com.amazonaws.cloudhsm.examples.crypto.symmetric.AESGCMEncryptDecryptExample().decrypt(migrationRunnerObject.transformation, (CaviumAESKey) ck, cipherText, iv, migrationRunnerObject.aad, migrationRunnerObject.tagLengthInBytes);
		System.out.println("Decrypted Text = "+new String(decryptedText));
	}
}
