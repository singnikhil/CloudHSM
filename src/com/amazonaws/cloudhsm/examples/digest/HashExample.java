package com.amazonaws.cloudhsm.examples.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import javax.xml.bind.DatatypeConverter;

import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;

public class HashExample {
	String plainText = "This is a Sample PLain Text!";
	String hashAlgo = "SHA-512";
	public static void main(String[] z) {
		LoginLogoutExample.loginWithExplicitCredentials();
		System.out.println("I Rule!");
		HashExample obj = new HashExample();
		byte[] hash = obj.getHash(obj.plainText, obj.hashAlgo);

		System.out.println("Hash : " + DatatypeConverter.printHexBinary(hash));
		LoginLogoutExample.logout();
	}

	public byte[] getHash(String message, String hashAlgo) {
		try {
			MessageDigest md = MessageDigest.getInstance(hashAlgo, "Cavium");
			md.update(message.getBytes());
			byte[] hash = md.digest();
			return hash;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
	}
}
