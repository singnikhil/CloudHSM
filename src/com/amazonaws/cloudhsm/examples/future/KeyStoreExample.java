package com.amazonaws.cloudhsm.examples.future;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchProviderException;

public class KeyStoreExample {

	public static void main(String[] args) {
		System.out.println("I Rule!");
		
	}
	
	public void createKeyStore() {
		try {
			KeyStore ks =  KeyStore.getInstance("", "Cavium");
		} catch (KeyStoreException | NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}
