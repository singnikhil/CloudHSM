package com.amazonaws.cloudhsm.examples.key.asymmetric;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import javax.crypto.KeyAgreement;

import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumECPrivateKey;
import com.cavium.key.CaviumECPublicKey;

public class ECKeyAgreement {

	public static void main(String[] args) {
		System.out.println("I Rule!");
		LoginLogoutExample.loginWithExplicitCredentials();
		ECAsymmetricKeyGeneration ecAsymmetricKeyGenerationObject = new ECAsymmetricKeyGeneration();
		KeyPair keyPair1 = ecAsymmetricKeyGenerationObject.generateECKeyPair("secp256r1", true);
		KeyPair keyPair2 = ecAsymmetricKeyGenerationObject.generateECKeyPair("secp256r1", true);
		ECKeyAgreement obj  = new ECKeyAgreement();
		
		//Generating Shared Secret by using private key from KeyPair1 and Public Key from KeyPair2  
		byte[] sharedSecret1 = obj.performKeyAgreement((CaviumECPrivateKey)keyPair1.getPrivate(), (CaviumECPublicKey)keyPair2.getPublic());
		//Generating Shared Secret by using private key from KeyPair2 and Public Key from KeyPair1
		byte[] sharedSecret2 = obj.performKeyAgreement((CaviumECPrivateKey)keyPair2.getPrivate(), (CaviumECPublicKey)keyPair1.getPublic());
		//Comparing Shared Secrets
		System.out.println(Base64.getEncoder().encodeToString(sharedSecret1));
		System.out.println(Base64.getEncoder().encodeToString(sharedSecret2));
		
		//Due to security issues, you should not use this shared secret directly
		//Instead you should derive another key from this shared secret using any KBKDF and use it for crypto operations.
		LoginLogoutExample.logout();
	}

	public byte[] performKeyAgreement(CaviumECPrivateKey privateKey, CaviumECPublicKey publicKey) {
	    try {
			KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "Cavium");
			keyAgreement.init(privateKey);
			keyAgreement.doPhase(publicKey, true);
			byte[] aesSecretKey = keyAgreement.generateSecret();
			return aesSecretKey;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	    return null;
	}
}