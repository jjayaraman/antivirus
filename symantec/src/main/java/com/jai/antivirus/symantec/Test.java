package com.jai.antivirus.symantec;

import java.io.File;
import java.io.IOException;

public class Test {

	public static void main(String[] args) {

		// meth1();
		meth2();

	}

	private static void meth1() {
		String fileName = "BR.RD. 13(2) for IT.xlsx";

		String TMP_FOLDER = "/tmp/symantecscan/";
		int endIndex = fileName.lastIndexOf(".");

		File tempFile = new File(TMP_FOLDER + fileName.substring(0, endIndex) + "_" + "20170106103059" + fileName.substring(endIndex));

		System.out.println(tempFile.getAbsolutePath());

		try {
			System.out.println(tempFile.getCanonicalPath());
		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println(tempFile.getPath());
		System.out.println(tempFile.getName());
	}

	private static void meth2() {

		String TMP_FOLDER = "C:/file";
		File folder = new File(TMP_FOLDER);

		if (folder.exists()) {
			if (folder.listFiles().length > 1) {
				System.out.println("Folder exists and has " + folder.listFiles().length + " file(s) in it...");
			} else {
				System.out.println("Folder exists and has NO files in it...");
			}
		} else {
			System.out.println("Folder does not exists ...");
		}

	}

}
