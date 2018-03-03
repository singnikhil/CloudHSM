package com.amazonaws.cloudhsm.examples.main;

import java.util.Scanner;

public class CloudHSMSampleRunner {
	public static void main(String[] z ) {
		System.out.println("I Rule");
		Scanner sc = new Scanner(System.in);
		boolean doExit = false;
		while(!doExit) {
		String input = sc.nextLine();
	     
	     if(input.equals("exit")) {
	    	 doExit = true;
	     }
		}
	}
	//public static void execute
}
