package com.amazonaws.cloudhsm.examples.digest;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.Mac;
import javax.xml.bind.DatatypeConverter;

import com.amazonaws.cloudhsm.examples.key.symmetric.AESSymmetricKeyGeneration;
import com.amazonaws.cloudhsm.examples.operations.KeyManagement;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumAESKey;

public class HMACExample {

	String message  = "This is a plain Text";
	String macAlgorithm= "HmacSHA512";

	public static void main(String[] z) {
		LoginLogoutExample.loginWithExplicitCredentials();
		System.out.println("I Rule!");
		Key aesKey = new AESSymmetricKeyGeneration().generateAESKey(256, true);
		//Key aesKey = KeyManagement.getKey(262376);

		HMACExample obj = new HMACExample();
		
		byte[] mac= obj.getHmac(obj.message, obj.macAlgorithm, (CaviumAESKey)aesKey);
		System.out.println("HMAC : " + DatatypeConverter.printHexBinary(mac));
		LoginLogoutExample.logout();
	}

	public byte[] getHmac(String message, String macAlgorithm, CaviumAESKey key) {
		try {
			System.out.println("Key Handle = "+key.getHandle());
			Mac mac = Mac.getInstance( macAlgorithm,"Cavium");
			mac.init(key);
			mac.update(message.getBytes());
			byte[] hmacValue = mac.doFinal();
			return hmacValue;

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