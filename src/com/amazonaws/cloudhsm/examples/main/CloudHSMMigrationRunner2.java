package com.amazonaws.cloudhsm.examples.main;

import java.security.Key;
import java.util.Arrays;

import com.amazonaws.cloudhsm.classic.examples.crypto.symmetric.AESEncryptDecryptExample;
import com.amazonaws.cloudhsm.classic.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.classic.examples.operations.LoginLogoutExample;
import com.amazonaws.cloudhsm.examples.operations.KeyManagement;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumKey;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.provider.key.LunaSecretKey;

public class CloudHSMMigrationRunner2 {

	//16 = GENERIC_SECRET, 18 = RC4, 21 = DES3, 31 = AES
	
	
	public static void main(String[] args) {
		System.out.println("I Rule!");
		LoginLogoutExample.loginToPartition("haGroup", "passw0rd@123");
		int lunaKeyHandle = 0;
		LunaKey lunaKey = new LunaKey(lunaKeyHandle);
		int keySize = lunaKey.getKeySize();
		String algo = lunaKey.getAlgorithm();
		long keyClass = lunaKey.GetKeyClass();
		long keyType = lunaKey.GetKeyType(algo);
		
	}
}
