package com.amazonaws.cloudhsm.examples.crypto.asymmetric;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


import com.amazonaws.cloudhsm.examples.key.asymmetric.RSAAsymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;

public class RSAAsymmetricEncryptDecryptExample {

	String plainText = "This is a Sample PLain Text!";
	String transformation  = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";

	String[] transformationArray={"RSA/ECB/NoPadding","RSA/ECB/PKCS1Padding","RSA/ECB/OAEPPadding","RSA/ECB/OAEPWithSHA-1ANDMGF1PADDING","RSA/ECB/OAEPWithSHA-224ANDMGF1Padding","RSA/ECB/OAEPWithSHA-256ANDMGF1Padding","RSA/ECB/OAEPWithSHA-384ANDMGF1Padding","RSA/ECB/OAEPWithSHA-512ANDMGF1Padding"};
	public static void main(String[] z) {
		LoginLogoutExample.loginWithExplicitCredentials();
		KeyPair kp = new RSAAsymmetricKeyGeneration().generateRSAKeyPair(4096,  new BigInteger("65537"), true);
		RSAAsymmetricEncryptDecryptExample obj = new RSAAsymmetricEncryptDecryptExample();
		for(String transformations: obj.transformationArray) {
			CaviumRSAPrivateKey privKey = (CaviumRSAPrivateKey) (RSAPrivateKey) kp.getPrivate();
			CaviumRSAPublicKey pubKey = (CaviumRSAPublicKey) (RSAPublicKey) kp.getPublic();
			System.out.println("Private Key Encryption Public Key Decryption");
			byte[] cipherText = obj.asymmetricKeyEncryption(transformations, privKey, obj.plainText);
			System.out.println("CipherText = " + Base64.getEncoder().encodeToString(cipherText));
			String plainText = obj.asymmetricKeyDecryption(transformations, pubKey, cipherText);
			System.out.println("PlainText = " + plainText);
			System.out.println("Public Key Encryption Private Key Decryption");
			cipherText = obj.asymmetricKeyEncryption(transformations, pubKey, obj.plainText);
			System.out.println("CipherText = " +Base64.getEncoder().encodeToString(cipherText));
			plainText = obj.asymmetricKeyDecryption(transformations, privKey, cipherText);
			System.out.println("PlainText = " + plainText);
		}
		LoginLogoutExample.logout();
	}

	public byte[] asymmetricKeyEncryption(String transformation, Key key, String plainText) { 
		try {
			Cipher cipher = Cipher.getInstance(transformation, "Cavium");
			cipher.init(Cipher.ENCRYPT_MODE, key);
			cipher.update(plainText.getBytes());
			byte[] cihperText = cipher.doFinal();
			return cihperText;
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
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

	public String asymmetricKeyDecryption(String transformation, Key key, byte[] cipherText) { 
		try {
			Cipher cipher = Cipher.getInstance(transformation, "Cavium");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] plainText = cipher.doFinal(cipherText);
			return new String(plainText);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
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
