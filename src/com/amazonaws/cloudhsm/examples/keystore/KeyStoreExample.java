package com.amazonaws.cloudhsm.examples.keystore;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.Base64;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509ExtendedKeyManager;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import com.amazonaws.cloudhsm.examples.digest.SignatureExample;
import com.amazonaws.cloudhsm.examples.operations.LoginLogoutExample;
import com.cavium.key.CaviumRSAKey;
import com.cavium.key.CaviumRSAPrivateKey;

import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Collection;
import javax.net.ssl.*;

public class KeyStoreExample {
	public static void main(String[] z) {
		LoginLogoutExample.loginWithExplicitCredentials();
		System.out.println("I Rule!");
		
		KeyStoreExample obj = new KeyStoreExample();
		
		System.out.println("Getting Private Key");
		
		CaviumRSAPrivateKey privKey = obj.getPrivateKey("");
		
		System.out.println("Getting Cert chain");
		
		X509Certificate[] chain = obj.getCertificate("/etc/letsencrypt/live/hsm.obscure.ninja/", "clientAuthCert.crt");
		
		System.out.println("Creating SSL Connection!!");
		obj.validateKeyAndCert(privKey, chain);
		obj.initalizeSSLConnection( privKey, chain); 
		LoginLogoutExample.logout();
	}
	
	public void validateKeyAndCert(CaviumRSAPrivateKey rsaPrivateKey, X509Certificate[] chain) {
		X509Certificate cert = chain[0];
		System.out.println(cert.getSubjectDN());
        RSAPublicKey rsaPublicKey = (RSAPublicKey) cert.getPublicKey();
		SignatureExample obj = new SignatureExample();

        byte[] signature = obj.signMessage("Message to be signed", "SHA1withRSA", (CaviumRSAPrivateKey) rsaPrivateKey);
		System.out.println("Signature : " + Base64.getEncoder().encodeToString(signature));
		boolean isVerificationSuccessful = obj.verifySign("Message to be signed", "SHA1withRSA", rsaPublicKey, signature);
		System.out.println("***************************************");
		
		System.out.println("isVerificationSuccessful = " + isVerificationSuccessful);
		
		System.out.println("***************************************");
        
	}

	public CaviumRSAPrivateKey getPrivateKey(String alias) {
		CaviumRSAKey rsaKey = null;
		Key rsaPrivateKey = null ;
		try {
			KeyStore ks = KeyStore.getInstance("Cavium","Cavium");
			ks.load(null, null);
			 rsaPrivateKey = ks.getKey(alias,null);
			
			rsaKey= (CaviumRSAPrivateKey)rsaPrivateKey;
			System.out.println(rsaKey.getHandle());
			System.out.println(rsaKey.getSize());
			//System.out.println(Base64.getEncoder().encode(rsaKey.getEncoded()));
		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (UnrecoverableKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}  catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return (CaviumRSAPrivateKey) rsaKey; 
	}

	public X509Certificate[] getCertificate(String certFilePath, String certFileName) {
		CertificateFactory certFactory;
		FileInputStream fileInputStream;
		Collection<X509Certificate> certificates = null;

		try {
			certFactory = CertificateFactory.getInstance("X.509");
			fileInputStream = new FileInputStream (certFilePath + "/" +  certFileName);
			certificates = (Collection<X509Certificate>) certFactory.generateCertificates(fileInputStream);
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		}
		return certificates.toArray(new X509Certificate[0]);
	}

	public void initalizeSSLConnection(CaviumRSAPrivateKey privKey, X509Certificate[] chain) {
		SSLContext sslctx;
		try {
			sslctx = SSLContext.getInstance("TLSv1.2");
			System.out.println("Got TLSv1.2 Instance!");
			ClientCertKeyManager keyManager = new ClientCertKeyManager(privKey, chain);
			System.out.println("Got ClientCertKeyManager!");

			sslctx.init(new KeyManager[] { keyManager }, null, new SecureRandom());
			SSLSocketFactory ssf = sslctx.getSocketFactory();
			HttpsURLConnection.setDefaultSSLSocketFactory(ssf);

			System.out.println("Creating Https Connection!");

			URL url = new URL("https://hsm.obscure.ninja");
			URLConnection conn = url.openConnection();
			System.out.println("Connection Open!");
			InputStream is = conn.getInputStream();
			System.out.println("Got InputStream!");
			InputStreamReader inputStreamReader = new InputStreamReader(is);

			System.out.println("Got InputStreamreader!");

			char[] cbuf = new char[10];
			int read = inputStreamReader.read();

			System.out.println("Reading inputStream!");

			while (	read!=-1) {
				 char character = (char) read;
				 System.out.print(character);
				 read = inputStreamReader.read();
			}

			is.close();
			
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (KeyManagementException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (MalformedURLException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
