package com.amazonaws.cloudhsm.classic.examples.operations;

import com.safenetinc.luna.LunaSlotManager;

public class LoginLogoutExample {
	public static LunaSlotManager slotManager = null;

	public static void main(String[] z) {
		System.out.println("I Rule!!");
		 boolean loginStatus = loginToPartition("haGroup", "passw0rd@123");
		 System.out.println("Login Successful? : " + loginStatus);
		logout();
	}

	public static boolean loginToPartition(String partition, String password) {
		slotManager =  LunaSlotManager.getInstance();
		boolean loginStatus =false;
		//System.out.println("Number of slots: " + slotManager.getNumberOfSlots());
        for (int i = 1; i <= slotManager.getNumberOfSlots(); i++) {
           //Checking if token is present in Slot
            if (slotManager.isTokenPresent(i)) {
            	//Getting partitionLabel
                String tokenlabel = slotManager.getTokenLabel(i);
                //System.out.println("Slot: " + i + " token label: " + tokenlabel);
                if(partition.equalsIgnoreCase(tokenlabel)) {
                	loginStatus = slotManager.login(tokenlabel, password) ;
                }
            }
        }
        return loginStatus;
	}
	
	public static void logout() {
		 slotManager.logout();
	}
}