package com.java.antivirus.clamav;

import java.io.BufferedInputStream;
import java.io.IOException;

/**
 * Helper class to execute clamscan
 *
 *
 * @author jjayaraman
 *
 */
public class ClamAvHelper {

	public static void main(String[] args) {

		if (args.length != 1) {
			System.out.println("Please supply a file name to scan. Example usage : ClamScan templates.zip");
		} else {
			System.out.println("About to virus scan the file : " + args[0]);
			scanFile(args[0]);
		}

		System.out.println("End...");
	}

	private static void scanFile(String file) {

		System.out.println("Scanning file : " + file + ". Please wait......");
		byte[] result = null;

		try {
			Process process = Runtime.getRuntime().exec("clamscan " + file);

			process.waitFor();

			BufferedInputStream bis = new BufferedInputStream(process.getInputStream());
			result = new byte[bis.available()];
			bis.read(result);

			System.out.println("Result : " + new String(result));

		} catch (IOException | InterruptedException e) {
			e.printStackTrace();
		}
	}

}
