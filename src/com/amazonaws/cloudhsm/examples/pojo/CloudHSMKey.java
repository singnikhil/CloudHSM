package com.amazonaws.cloudhsm.examples.pojo;

import com.cavium.key.CaviumKey;

public class CloudHSMKey {
	private CaviumKey key;
	private String label ;
	private long handle ;
	private boolean isExtractable ;
	private boolean isPersistant ;
	private String algorithm;
	private int keySize;
	
	public CaviumKey getKey() {
		return key;
	}
	public void setKey(CaviumKey key) {
		this.key = key;
	}
	public String getLabel() {
		return label;
	}
	public void setLabel(String label) {
		this.label = label;
	}
	public long getHandle() {
		return handle;
	}
	public void setHandle(long handle) {
		this.handle = handle;
	}
	public boolean isExtractable() {
		return isExtractable;
	}
	public void setExtractable(boolean isExtractable) {
		this.isExtractable = isExtractable;
	}
	public boolean isPersistant() {
		return isPersistant;
	}
	public void setPersistant(boolean isPersistant) {
		this.isPersistant = isPersistant;
	}
	public String getAlgorithm() {
		return algorithm;
	}
	public void setAlgorithm(String algorithm) {
		this.algorithm = algorithm;
	}
	public int getKeySize() {
		return keySize;
	}
	public void setKeySize(int keySize) {
		this.keySize = keySize;
	}
	
}