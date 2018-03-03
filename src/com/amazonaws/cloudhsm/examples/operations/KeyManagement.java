package com.amazonaws.cloudhsm.examples.operations;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.amazonaws.cloudhsm.examples.key.asymmetric.RSAAsymmetricKeyGeneration;
import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.ImportKey;
import com.cavium.cfm2.Util;
import com.cavium.key.CaviumAESKey;
import com.cavium.key.CaviumDES3Key;
import com.cavium.key.CaviumECPrivateKey;
import com.cavium.key.CaviumECPublicKey;
import com.cavium.key.CaviumKey;
import com.cavium.key.CaviumKeyAttributes;
import com.cavium.key.CaviumRSAPrivateKey;
import com.cavium.key.CaviumRSAPublicKey;
import com.cavium.key.parameter.CaviumKeyGenAlgorithmParameterSpec;
import com.cavium.key.parameter.CaviumRSAKeyGenParameterSpec;
import com.fasterxml.jackson.databind.deser.Deserializers.Base;

public class KeyManagement {

	public static void main(String[] args) throws Exception {
		LoginLogoutExample.loginWithExplicitCredentials();
		
		//SecretKey key = new SecretKeySpec( new byte[] { 0, 17, 34, 51, 68, 85, 102, 119, -120, -103, -86, -69, -52, -35, -18, -1 }, "AES");
		//Generate a new AES Key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		SecretKey key = keyGen.generateKey();
		//Print it's bits in base 64 encoded format 
		System.out.println("Base64 Encoded key = "  + Base64.getEncoder().encodeToString(key.getEncoded()));
		//Invoke import method. This will import the key into the HSM and return key handle
		long importedKeyHandle = importKey( key, "ImportedAESKey", false, true);
		System.out.println("Key Handle after importing key into HSM" + importedKeyHandle);
		//Try to export same key from the HSM
		Key exportedKey = exportKey(importedKeyHandle); 
		//Print encoded bits in base64 format to compare with original key
		System.out.println("Base64 Encoded value of exported Key = "  + Base64.getEncoder().encodeToString(exportedKey.getEncoded()));

		LoginLogoutExample.logout();
	}

	public static CaviumKey getKey(long handle) {
		try {
			byte[] keyAttribute = Util.getKeyAttributes(handle);
			CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);
			if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
				CaviumAESKey aesKey = new CaviumAESKey(handle, cka);
				return aesKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
				CaviumRSAPrivateKey privKey = new CaviumRSAPrivateKey(handle, cka);
				return privKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
				CaviumRSAPublicKey pubKey = new CaviumRSAPublicKey(handle, cka);
				return pubKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_DES3) {
				CaviumDES3Key des3Key = new CaviumDES3Key(handle, cka);
				return des3Key;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
				CaviumECPublicKey ecPublicKey = new CaviumECPublicKey(handle, cka);
				return ecPublicKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
				CaviumECPrivateKey ecPrivateKey = new CaviumECPrivateKey(handle, cka);
				return ecPrivateKey;
			}
		} catch (CFM2Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;		
	}

	public static void deteleKey(long handle) throws Exception {
		CaviumKey ck = getKey(handle);
		Util.deleteKey(ck);
		System.out.println("Key Deleted!");
	}

	public static Key exportKey(long handle) {
		try {
			byte[] keyAttribute = Util.getKeyAttributes(handle);
			CaviumKeyAttributes cka = new CaviumKeyAttributes(keyAttribute);
			if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_AES) {
				byte[] encoded = Util.exportKey( handle);
				Key aesKey = new SecretKeySpec(encoded, 0, encoded.length, "AES");
				return aesKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
				byte[] encoded = Util.exportKey( handle);
				PrivateKey privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(encoded));
				return privateKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_RSA && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
				PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(cka.getModulus(), cka.getPublicExponent()));
				return publicKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_DES3) {
				byte[] encoded = Util.exportKey( handle);
				Key des3Key = new SecretKeySpec(encoded, 0, encoded.length, "DESede");
				return des3Key;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PUBLIC_KEY) {
				byte[] encoded = Util.exportPublicKey(handle);
				X509EncodedKeySpec x509PublicKeySpec = new X509EncodedKeySpec(encoded);
				ECPublicKeySpec ecPublicKeySpec = Util.convertX509ToECPublicKeySpec(x509PublicKeySpec);
				PublicKey ecPublicKey = KeyFactory.getInstance("EC").generatePublic(ecPublicKeySpec);
				return ecPublicKey;
			}
			else if(cka.getKeyType() == CaviumKeyAttributes.KEY_TYPE_EC && cka.getKeyClass() == CaviumKeyAttributes.CLASS_PRIVATE_KEY) {
				byte[] encoded = Util.exportKey(handle);
				Key ecPrivateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(encoded));
				return ecPrivateKey;
			}
		} catch (BadPaddingException | CFM2Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} 
		return null;
	}

	public static long importKey(Key key, String keyLabel, boolean isExtractable, boolean isPersistent) {
		//Creating a new Key Parameter Spec to identify Key by Label, is it's Extractable and if it's persistant.
		CaviumKeyGenAlgorithmParameterSpec spec = new CaviumKeyGenAlgorithmParameterSpec(keyLabel, isExtractable, isPersistent);
		try {
			Key importedKey = ImportKey.importKey(key, spec);
			CaviumKey cavImportedKey = (CaviumKey)importedKey;
			return cavImportedKey.getHandle();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return -1;
		}
	}

	public static void getRSAComponents(CaviumRSAPublicKey cavKey) {
		 int[] arrayOfInt = new int[1];
		try {
			byte[] encodedByte = cavKey.getEncoded();
			System.out.println(Base64.getEncoder().encodeToString(Util.getRSAPrivateKeyComponents(encodedByte, arrayOfInt)));
		} catch (CFM2Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}