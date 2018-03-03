package com.amazonaws.cloudhsm.examples.digest;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Date;

import com.amazonaws.cloudhsm.examples.key.asymmetric.ECAsymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.key.asymmetric.RSAAsymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.operations.KeyManagement;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.cfm2.LoginManager;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;

public class SignatureExample{

	String sampleMessage = "This is a sample Message";
	String signingAlgo = "SHA256withECDSA";
	public static void main(String[] args) throws Exception {
		System.out.println("I Rule!");
		LoginLogoutExample.loginWithExplicitCredentials();
		SignatureExample obj = new SignatureExample();
		KeyPair kp = new ECAsymmetricKeyGeneration().generateECKeyPair("prime256v1", true);

		byte[] signature = obj.signMessage(obj.sampleMessage, obj.signingAlgo, (CaviumRSAPrivateKey)kp.getPrivate());
		System.out.println("Signature : " + Base64.getEncoder().encodeToString(signature));
		boolean isVerificationSuccessful = obj.verifySign(obj.sampleMessage, obj.signingAlgo, (CaviumRSAPublicKey)kp.getPublic(), signature);
		System.out.println("isVerificationSuccessful" + isVerificationSuccessful);
		LoginLogoutExample.logout();
	}

	public byte[] signMessage(String message, String signingAlgo, CaviumRSAPrivateKey privateKey) {
		try {
			Signature sig = Signature.getInstance(signingAlgo, "Cavium");
			sig.initSign(privateKey);
			sig.update(message.getBytes()); 
			byte[] signature = null;
			signature = sig.sign();
			return signature;

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}

	public boolean verifySign(String message, String signingAlgo, RSAPublicKey publicKey, byte[] signature) {
		try {
			Signature sig = Signature.getInstance(signingAlgo, "Cavium");
			sig.initVerify(publicKey);
			sig.update(message.getBytes());
			boolean isVerificationSuccessful = sig.verify(signature);
			return isVerificationSuccessful;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
	}
}