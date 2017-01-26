package com.jai.antivirus.symantec;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

public class FileTest {

	public static void main(String[] args) {

		String fileName = "fileTest.txt";

		String TMP_FOLDER = "/home/weblogic/jay/";

		int endIndex = fileName.lastIndexOf(".");
		File tempFile = new File(TMP_FOLDER + fileName.substring(0, endIndex) + "_20170106103059" + fileName.substring(endIndex));

		if(tempFile.exists()) {
			System.out.println("canRead : " +tempFile.canRead());
			System.out.println("canWrite : " +tempFile.canWrite());
			System.out.println("canExecute : " +tempFile.canExecute());
		}

		tempFile.setExecutable(true, false);

		try {
			FileWriter fileWriter = new FileWriter(tempFile);
			fileWriter.write("This is an exmaple for file permissions....");
			fileWriter.close();

		} catch (IOException e) {
			e.printStackTrace();
		}
		System.out.println("Done...");
	}

}
