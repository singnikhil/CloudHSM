package com.amazonaws.cloudhsm.classic.examples.key.symmetric;

import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import com.amazonaws.cloudhsm.classic.examples.operations.LoginLogoutExample;
import com.safenetinc.luna.provider.key.LunaSecretKey;

public class AESSymmetricKeyGeneration {

	public static void main(String[] z) {
		LoginLogoutExample.loginToPartition("haGroup", "passw0rd@123");
		System.out.println(LoginLogoutExample.slotManager.areSecretKeysExtractable());
		new AESSymmetricKeyGeneration().generateAESKey(128, "NewKey121", true, false);
		LoginLogoutExample.logout();
	}

	public Key generateAESKey(int keySize, String alias, boolean isPersistent, boolean isExtractable ) {
		KeyGenerator keyGen;
		try {
			if(isExtractable) {
				System.out.println("Setting Key Extractable!!");
				makeKeyExtractable();
				System.out.println("Key is Extractable!");
			}
			keyGen = KeyGenerator.getInstance("AES","LunaProvider");
			keyGen.init(keySize);
			SecretKey aesKey = keyGen.generateKey();
			System.out.println("Key Generated!");
			System.out.println(Base64.getEncoder().encodeToString(aesKey.getEncoded()));
			if(aesKey instanceof LunaSecretKey) {
				LunaSecretKey lunaKey = (LunaSecretKey) aesKey;
				//Save Key Handle. You'll need this to perform encrypt/decrypt operation in future.
				System.out.println("Key Handle = " + lunaKey.GetKeyHandle());
				//Get Key Label. This Label is generated by SDK for this key
				System.out.println("Key Label = " + lunaKey.GetAlias());

				//By default Keys are not persistent. Set them Persistent here
				System.out.println("Is Key Persistent? : " + lunaKey.IsKeyPersistent());
				//System.out.println(Base64.getEncoder().encodeToString(lunaKey.ExtractSecretKey()));
				if(isPersistent) {
					System.out.println("Setting Key as Persistent:");
					makeKeyPersistant(lunaKey, alias);
					System.out.println("Key is Persistent!");
					System.out.println("Key Handle = " + lunaKey.GetKeyHandle());
				}

				System.out.println("Is Key Persistant? : " + lunaKey.IsKeyPersistent());

				//Verify Key type and Size
				System.out.println("Key Algo : " + lunaKey.getAlgorithm());
				System.out.println("Key Size : " + lunaKey.getKeySize());

			}
			return aesKey;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return null;
	}

	public void makeKeyPersistant(Key key, String alias) {
		try {
			KeyStore keyStore = KeyStore.getInstance("Luna");
			keyStore.load(null, null);
			keyStore.setKeyEntry(alias, key, null, null);
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public void makeKeyExtractable() {
		LoginLogoutExample.slotManager.setSecretKeysExtractable(true);
	}
}