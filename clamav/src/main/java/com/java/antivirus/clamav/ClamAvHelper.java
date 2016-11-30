package com.java.antivirus.clamav;

import java.io.BufferedInputStream;
import java.io.IOException;

public class ClamAvHelper {

	public static void main(String[] args) {

		byte[] result = null;

		try {
			Process process = Runtime.getRuntime().exec("clamscan");

			if (process.waitFor() == 0) {
				System.out.println("Successfully executed...");
			} else {

				BufferedInputStream bis = new BufferedInputStream(process.getInputStream());
				result = new byte[bis.available()];
				bis.read(result);

				System.out.println("Result : " + new String(result));
			}

		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}

		System.out.println("End...");
	}

}
