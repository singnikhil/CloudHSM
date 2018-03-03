package com.amazonaws.cloudhsm.examples.operations;

import com.cavium.cfm2.CFM2Exception;
import com.cavium.cfm2.LoginManager;

public class LoginLogoutExample {
	public static void main(String[] z) {
		System.out.println("I Rule!!");
		System.out.println("*********** Logging in Using Hardcoded Credentials ***********");
		loginWithExplicitCredentials();
		
		System.out.println("*********** Logging in Using System.Properties ***********");	
		loginUsingJavaProperties();
		
		System.out.println("*********** Logging in Using Environment Variables ***********");	
		loginWithEnvVariables();
		
		System.out.println("Logging out of Session");
		logout();
	}

	public static void loginWithExplicitCredentials() {
		LoginManager lm = LoginManager.getInstance();
		lm.loadNative();
		try {
			lm.login("PARTITION_1", "cryptoUser", "passw0rd@123");
			int appID = lm.getAppid();
			//System.out.println("App ID = " + appID);
			int sessionID = lm.getSessionid();
			//System.out.println("Session ID = " + sessionID);
		} catch (CFM2Exception e) {
			e.printStackTrace();
		}
	}

	public static void loginUsingJavaProperties() {
		System.setProperty("HSM_PARTITION","PARTITION_1"); 
		System.setProperty("HSM_USER","cryptoUser"); 
		System.setProperty("HSM_PASSWORD","passw0rd@123");
		LoginManager lm = LoginManager.getInstance();
		lm.loadNative();
		try {
			lm.login();
			int appID = lm.getAppid();
			System.out.println("App ID = " + appID);
			int sessionID = lm.getSessionid();
			System.out.println("Session ID = " + sessionID);
		} catch (CFM2Exception e) {
			e.printStackTrace();
		}
	}

	public static void loginWithEnvVariables() {
		LoginManager lm = LoginManager.getInstance();
		lm.loadNative();
		try {
			lm.login();
			int appID = lm.getAppid();
			//System.out.println("App ID = " + appID);
			int sessionID = lm.getSessionid();
			//System.out.println("Session ID = " + sessionID);
		} catch (CFM2Exception e) {
			e.printStackTrace();
		}
	}
	
	public static void logout() {
		try {
			LoginManager.getInstance().logout();
		} catch (CFM2Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
}