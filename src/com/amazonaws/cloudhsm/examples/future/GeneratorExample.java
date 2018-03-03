package com.amazonaws.cloudhsm.examples.future;

import java.math.BigInteger;
import java.security.KeyPair;

import com.amazonaws.cloudhsm.examples.operations.KeyManagement;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.Generator;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumDES3Key;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;

public class GeneratorExample {

	public static void main(String[] args) {
		System.out.println("I Rule!");
		LoginLogoutExample.loginWithExplicitCredentials();
		try {
			//Create a RSA KeyPair by specifying key length, exponent, label for public and private keys and boolean for exportable and persistant respectively.  
			KeyPair kp= Generator.generateRSAKeyPair(2048, new BigInteger("65537"), "RSA Public Key", "RSA Private Key", true, true);
			CaviumRSAPrivateKey privKey = (CaviumRSAPrivateKey) kp.getPrivate();
			CaviumRSAPublicKey pubKey = (CaviumRSAPublicKey) kp.getPublic();
			System.out.println("Private Key Handle : " + privKey.getHandle());
			System.out.println("Public Key Handle : " + pubKey.getHandle());
			System.out.println("Encoded Private Key : " + privKey.getEncoded());
			System.out.println("Encoded Public Key : " + pubKey.getEncoded());
			System.out.println("Exported Encoded Private Key : " + KeyManagement.exportKey(privKey.getHandle()).getEncoded());
			System.out.println("Exported Encoded Public Key" + KeyManagement.exportKey(pubKey.getHandle()).getEncoded());

			//Create a AES Key by specifying key size, label and boolean for exportable and persistant.
			CaviumAESKey aesKey= (CaviumAESKey) Generator.generateAESKey(256, "AES Key usingGenerator", true, true);
			System.out.println("Encoded Key" + aesKey.getEncoded());
			System.out.println("AES Key Handle : " + aesKey.getHandle());
			System.out.println("Exported Encoded AES Key : " + KeyManagement.exportKey(aesKey.getHandle()).getEncoded());
			
			//Create a DES Key by specifying key size, label and boolean for exportable and persistant.
			CaviumDES3Key des3Key= (CaviumDES3Key) Generator.generateDESKey("3DES Key usingGenerator", true, true);
			System.out.println("Encoded Key" + des3Key.getEncoded());
			System.out.println("3DES Key Handle : " + des3Key.getHandle());
			System.out.println("Exported Encoded AES Key : " + KeyManagement.exportKey(des3Key.getHandle()).getEncoded());

		} catch (CFM2Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		LoginLogoutExample.logout();
	}
}