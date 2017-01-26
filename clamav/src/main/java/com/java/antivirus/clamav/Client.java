package com.java.antivirus.clamav;

import fi.solita.clamav.ClamAVClient;

public class Client {

	private static void scanBytes(byte[] data) throws Exception {
		ClamAVClient cl = new ClamAVClient("localhost", 3310);
		byte[] reply;
		try {
			reply = cl.scan(data);
		} catch (Exception e) {
			throw new RuntimeException("Could not scan the input", e);
		}
		if (!ClamAVClient.isCleanReply(reply)) {
			throw new Exception("aaargh. Something was found");
		}

	}

	public static void main(String[] args) {
		try {

			byte[] input = new String("test data to scan").getBytes();

			scanBytes(input);

		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("End..");
	}

}
