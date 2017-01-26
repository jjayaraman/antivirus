package com.jai.antivirus.symantec;

///////////////////////////////////////////////////////////////////////////////
//
//Copyright (c) 2016 Symantec Corporation. All rights reserved.
//THIS SOFTWARE CONTAINS CONFIDENTIAL INFORMATION AND TRADE SECRETS OF SYMANTEC CORPORATION.
//USE, DISCLOSURE OR REPRODUCTION IS PROHIBITED WITHOUT THE PRIOR EXPRESS WRITTEN PERMISSION OF
//SYMANTEC CORPORATION.
//The Licensed Software and Documentation are deemed to be commercial computer software as defined
//in FAR 12.212 and subject to restricted rights as defined in FAR Section 52.227-19 "Commercial
//Computer Software - Restricted Rights" and DFARS 227.7202, Rights in "Commercial Computer Software
//or Commercial Computer Software Documentation," as applicable, and any successor regulations, whether
//delivered by Symantec as on premises or hosted services.  Any use, modification, reproduction release,
//performance, display or disclosure of the Licensed Software and Documentation by the U.S. Government
//shall be solely in accordance with the terms of this Agreement.
//
//////////////////////////////////////////////////////////////////////////////

import java.util.Vector;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import com.symantec.scanengine.api.ConnectionAttempt;
import com.symantec.scanengine.api.InsightOptions;
import com.symantec.scanengine.api.Result;
import com.symantec.scanengine.api.Policy;
import com.symantec.scanengine.api.ThreatInfo;
import com.symantec.scanengine.api.ThreatInfoEx;
import com.symantec.scanengine.api.ScanEngine;
import com.symantec.scanengine.api.FileScanRequest;
import com.symantec.scanengine.api.StreamScanRequest;
import com.symantec.scanengine.api.ScanException;

/**
 * The sample code demonstrate how to use the Symantec Protection Engine API. This example demonstrates the use of both file-based scanning and stream
 * based scanning.
 *
 */

public class JavaAPICheck {
	// Options
	final static String fileForScanning = "file";
	final static String scanningMode = "streambased";
	final static String scanStreamFileLocal = "streamFileLocal";
	final static String scanServer = "server";
	final static String scanPolicy = "policy";
	final static String scanOutputFile = "output";
	final static String scanFileOriginalName = "originalname";
	final static String api = "api";
	final static String insightaggressionlevel = "insightaggressionlevel";
	final static String disableinsight = "disableinsight";
	final static String sourceip = "SourceIP";
	final static String sourceurl = "SourceURL";
	final static String digitallysigned = "digitallysigned";
	final static String md5hash = "MD5";
	final static String sha256 = "SHA256";
	final static String insightinfo = "reportinsightinfo";

	// Defaults value for options
	static String fileForScan = "";
	static int scanMode = 0;
	static int streamFileLocal = 0;
	//static String scanServers = "127.0.0.1:1344";
	static String scanServers = "eb2dv-web01:1344";
	static String setScanPolicy = "";
	static String scanOutput = null;
	static String scanFileOriginName = null;

	static Policy scPolicy = Policy.DEFAULT;
	static Vector scanEnginesForScanning = new Vector();
	static int isExtendedAPI = 0;
	static boolean disableInsightCall = false;
	static InsightOptions insightOptions;

	public JavaAPICheck() {
	}

	// Display usage
	public static void printUsage() {
		System.out.println("\nUsage: java JavaAPICheck [options] -file:<filetoscan>\n");
		System.out.println("Note: Defaults to filebased scanning..else mention streambased:1\n");
		System.out.println("<options:value>");
		System.out.println("-streambased:<0|1>");
		System.out.println("         Use value 1 to perform streambased scanning else default value 0 i.e. filebased scanning.\n");
		System.out.println("-streamFileLocal:<0|1>");
		System.out.println("         Use value 1 to auto stream if file available local else default to 0 i.e. file will not be auto streamed.");
		System.out.println("         This option is only applicable if streambased:1\n");
		System.out.println("-server:<IP>:<PORT>;<IP>:<PORT>;...");
		System.out.println("         Defaults to server 127.0.0.1:1344.");
		System.out.println("         Multiple servers can be specified for load balancing.\n");
		System.out.println("-policy:<scan|scanrepair|scanrepairdelete|scandelete>");
		System.out.println("         Defaults to Symantec Protection Engine Scan Policy\n");
		System.out.println("-output:<filename>");
		System.out.println("         Full path of the outputfilename\n");
		System.out.println("         Defaults to file.out in current directory.\n");
		System.out.println("-originalname:<filename>");
		System.out.println("         Original file name for documentation purpose\n");
		System.out.println("-api:<0|1|2>");
		System.out.println(
				"		 Use 2 to scan file with new Insight API's, facilitates to provide file context (SHA256, MD5, digital signing status, source URL, source IP, etc) along with file scan request.Scan result provides more information about threat detected and file details.\n\n");
		System.out.println("         Use value 1 to scan file with new API's, provides more information about threat detected.\n");
		System.out.println("         Use value 0 to scan file with legacy API's. Defaults to 0.\n");
		System.out.println("-disableinsight\tDisable insight scanning for file.\n\n");
		System.out.println("-insightaggressionlevel\t<1|2|3>\n\tInsight aggression level to be used for scanning.\n\n");
		System.out.println("-MD5\t<MD5 hash value of file.>\n\n");
		System.out.println("-SHA256\t<SHA256 hash value of file.>\n\n");
		System.out.println("-SourceIP\t<Source IP of the file.>\n\n");
		System.out.println("-SourceURL\t<Source URL of the file.>\n\n");
		System.out.println("-digitallysigned\t<File is not signed.>\n\n");
		System.out.println("-reportinsightinfo\t<0|1>\n\n\t0\tto disable insight result\n\n\t1\tto enable insight result");

	}

	// Print Result
	public static void printResult(Result result, boolean extendedInfo) {
		System.out.println("----------------------------------------------------------------------");
		System.out.println("Scanning file ........................................................");
		System.out.println("----------------------------------------------------------------------");
		System.out.println("Results ..............................................................");
		System.out.println("----------------------------------------------------------------------");
		System.out.println("File Scanned		: " + fileForScan);
		System.out.println("Scan Policy		: " + scPolicy);
		System.out.println("File Status		: " + result.getStatus());
		System.out.println("Total Infection		: " + result.getTotalInfection());
		System.out.println("Virus Def Date		: " + result.getDefinitionDate());
		System.out.println("Virus Def Revision No	: " + result.getDefinitionRevNumber());

		// SK - legacy case to print the threat info
		if (extendedInfo == false) {
			ThreatInfo[] virusIn = result.getThreatInfo();
			for (int i = 0; i < virusIn.length; i++) {

				System.out.println("File Name               : " + virusIn[i].getFileName());
				System.out.println("Violation Name          : " + virusIn[i].getViolationName());
				if (virusIn[i].getThreatCategory() != null) {
					System.out.println("Non Viral Threat Category : " + virusIn[i].getThreatCategory());
				}
				System.out.println("Violation Id            : " + virusIn[i].getViolationId());
				System.out.println("Disposition	        : " + virusIn[i].getDisposition());
				System.out.println("File Unscannable		: " + virusIn[i].getFileunscannable());
			}
		} else // print extended threat info
		{
			ThreatInfoEx[] virusIn = result.getThreatInfo();
			for (int i = 0; i < virusIn.length; i++) {

				System.out.println("File Name               : " + virusIn[i].getFileName());
				if (virusIn[i].getViolationName() != null)
					System.out.println("Violation Name	        : " + virusIn[i].getViolationName());
				// Since in new case viral and non viral both are getting treated as threats, it's better
				// to name the Non Viral Threat category as just a "Threat Category" while printing
				if (virusIn[i].getThreatCategory() != null) {
					System.out.println("Threat Category 	: " + virusIn[i].getThreatCategory());
				}
				if (virusIn[i].getViolationId() != null)
					System.out.println("Violation Id            : " + virusIn[i].getViolationId());
				if (virusIn[i].getDisposition() != null)
					System.out.println("Disposition	        : " + virusIn[i].getDisposition());
				if (virusIn[i].getFileunscannable() != null)
					System.out.println("File Unscannable        : " + virusIn[i].getFileunscannable());

				if (virusIn[i].getIsExtraThreatInfoPresent() == true) {
					if (virusIn[i].getUberCategory() != null)
						System.out.println("Uber Category           : " + virusIn[i].getUberCategory());
					if (virusIn[i].getSubCategoryID() != null)
						System.out.println("SubCategory ID          : " + virusIn[i].getSubCategoryID());
					if (virusIn[i].getCumulativeRiskRating() != null)
						System.out.println("Cumulative Risk Rating  : " + virusIn[i].getCumulativeRiskRating());

					if (virusIn[i].getPerformanceImpact() != null)
						System.out.println("Performance Impact      : " + virusIn[i].getPerformanceImpact());

					if (virusIn[i].getPrivacyImpact() != null)
						System.out.println("Privacy Impact          : " + virusIn[i].getPrivacyImpact());

					if (virusIn[i].getEaseOfRemoval() != null)
						System.out.println("Ease of Removal         : " + virusIn[i].getEaseOfRemoval());

					if (virusIn[i].getStealth() != null)
						System.out.println("Stealth        		: " + virusIn[i].getStealth());
					if (virusIn[i].getSubCategoryDescription().length() > 0)
						System.out.println("SubCategory Description : " + virusIn[i].getSubCategoryDescription());
				}
				if (virusIn[i].getInsightResult() != 0) {
					System.out.println("Insight Cache revocation Content Date		: " + result.getInsightCacheContentDate());
					System.out.println("Insight Cache revocation Content Revision No	: " + result.getInsightCacheContentRevNumber());
					System.out.println("Insight Settings Content Date		: " + result.getInsightSettingsContentDate());
					System.out.println("Insight Settings Content Revision No	: " + result.getInsightSettingsContentRevNumber());
					System.out.println("Insight symV Content Date		: " + result.getInsightsymVTContentDate());
					System.out.println("Insight symVT Content Revision No	: " + result.getInsightsymVTContentRevNumber());
					System.out.println("Insight Result : " + virusIn[i].getInsightResult());
					if (virusIn[i].getFileReputation() != null)
						System.out.println("File Repuation :" + virusIn[i].getFileReputation());
					if (virusIn[i].getFileAge() != null)
						System.out.println("File Age :" + virusIn[i].getFileAge());
					if (virusIn[i].getFilePrevalence() != null)
						System.out.println("File Prevalence :" + virusIn[i].getFilePrevalence());
					if (virusIn[i].getFileType() != null)
						System.out.println("File Type :" + virusIn[i].getFileType());
					if (virusIn[i].getFileSHA256() != null)
						System.out.println("File SHA256 :" + virusIn[i].getFileSHA256());
				}
				if (virusIn[i].isAPKResultInfoPresent() == true) {
					System.out.println("APK Result Code : " + virusIn[i].getAPKResultCode());
				}
			}
		}
		ConnectionAttempt[] conTry = result.getIPTries();
		for (int x = 0; x < conTry.length; x++) {
			System.out.println("Symantec Protection Engine IP		: " + conTry[x].getIPAddress());
			System.out.println("Symantec Protection Engine Port	: " + conTry[x].getPortNumber());
			System.out.println("Symantec Protection Engine Port	: " + conTry[x].getErrString());
		}
	}

	// Execution
	public static void main(String args[]) {
		int argsCorrectMatch = 0;
		String errMsg = "";
		boolean errorArgs = false;
		String defaultResultFile = "file.out";
		InsightOptions insightOptions = null;

		if (args.length < 1) {
			JavaAPICheck.printUsage();
		} else {
			int totalArgs = args.length;
			insightOptions = new InsightOptions();
			for (int i = 0; i < totalArgs; i++) {
				try {
					String option = "";
					String value = "";
					if (args[i].equals("-disableinsight")) {
						disableInsightCall = true;
						insightOptions = null;
						argsCorrectMatch++;
					} else {
						option = args[i].substring(args[i].indexOf("-") + 1, args[i].indexOf(":"));
						value = args[i].substring(args[i].indexOf(":") + 1, args[i].length());
					}

					if (option.equals(fileForScanning)) {
						fileForScan = value;
						argsCorrectMatch++;
					} else if (option.equals(scanningMode)) {
						scanMode = Integer.parseInt(value);
						argsCorrectMatch++;
					} else if (option.equals(scanStreamFileLocal)) {
						streamFileLocal = Integer.parseInt(value);
						argsCorrectMatch++;
					} else if (option.equals(digitallysigned)) {
						if (insightOptions != null)
							insightOptions.setFileDigitallySigned(Integer.parseInt(value));
						argsCorrectMatch++;
					} else if (option.equals(insightaggressionlevel)) {
						if (insightOptions != null)
							insightOptions.setInsightAggressionLevel(Integer.parseInt(value));
						argsCorrectMatch++;
					} else if (option.equals(sha256)) {
						if (insightOptions != null)
							insightOptions.setFileSHA256Hash(value);
						argsCorrectMatch++;
					} else if (option.equals(sourceip)) {
						if (insightOptions != null)
							insightOptions.setSourceIP(value);
						argsCorrectMatch++;
					} else if (option.equals(sourceurl)) {
						if (insightOptions != null)
							insightOptions.setSourceURL(value);
						argsCorrectMatch++;
					} else if (option.equals(md5hash)) {
						if (insightOptions != null)
							insightOptions.setFileMD5Hash(value);
						argsCorrectMatch++;
					} else if (option.equals(insightinfo)) {
						if (insightOptions != null)
							insightOptions.setReportInsightInfo(Integer.parseInt(value));
						argsCorrectMatch++;
					}

					else if (option.equals(scanServer)) {
						int ipPortCnt = 0;
						scanServers = value;

						String ipPort[] = value.split(";");

						for (int k = 0; k < ipPort.length; k++) {
							if (!(ipPort[k].trim().length() == 0)) {
								String ipPr[] = ipPort[k].split(":");

								if (ipPr.length != 2) {
									System.out.println("Incorrect Symantec Protection Engine IP:Port!! ");
									System.exit(1);
								} else {
									ScanEngine.ScanEngineInfo scanEngTobeUsed = new ScanEngine.ScanEngineInfo(ipPr[0].trim(),
											Integer.parseInt(ipPr[1].trim()));
									scanEnginesForScanning.add(scanEngTobeUsed);
								}
							}

						}

						argsCorrectMatch++;
					} else if (option.equals(scanPolicy)) {
						setScanPolicy = value;
						argsCorrectMatch++;
					} else if (option.equals(scanOutputFile)) {
						scanOutput = value;
						argsCorrectMatch++;
					} else if (option.equals(scanFileOriginalName)) {
						scanFileOriginName = value;
						argsCorrectMatch++;
					} else if (option.equals(api)) {
						isExtendedAPI = Integer.parseInt(value);
						argsCorrectMatch++;
					}
				} catch (ScanException ex) {
					// System.out.println(totalArgs);
					System.out.println(ex);
					System.exit(1);
				} catch (Exception ex) {
					System.out.println(totalArgs);
					System.out.println("Incorrect number of arguments !!" + ex);
					System.exit(1);
				}
			}

			if (argsCorrectMatch != totalArgs) {
				JavaAPICheck.printUsage();
				errorArgs = true;
				System.exit(1);
			}

			if (fileForScan.length() == 0) {
				System.out.println("\nFile to be scanned not found!!");
				errorArgs = true;
				System.exit(1);
			}

			if (setScanPolicy.length() != 0) {
				try {
					scPolicy = Policy.valueOf(setScanPolicy.trim().toUpperCase());
				} catch (Exception ex) {
					System.out.println("\nIncorrect Scan Policy!!");
					errorArgs = true;
					System.exit(1);
				}
			}

			if (!errorArgs) {
				if (scanEnginesForScanning.size() == 0) {
					ScanEngine.ScanEngineInfo scanEngTobeUsed = new ScanEngine.ScanEngineInfo("127.0.0.1", 1344);
					scanEnginesForScanning.add(scanEngTobeUsed);
				}

				if (scanMode == 0) {
					try {

						ScanEngine scanEngine = ScanEngine.createScanEngine(scanEnginesForScanning, 30000, 30000);
						if (isExtendedAPI == 0) {
							FileScanRequest fileScanReq = scanEngine.createFileScanRequest(fileForScan, scPolicy);
							Result result = fileScanReq.scanFile();
							printResult(result, false);

						} else if (isExtendedAPI == 1) {
							FileScanRequest fileScanReq = scanEngine.createFileScanRequest(fileForScan, scPolicy, true);
							Result result = fileScanReq.scanFile();
							printResult(result, true);
						} else {
							FileScanRequest fileScanReq = scanEngine.createFileScanRequest(fileForScan, scPolicy, disableInsightCall, insightOptions);
							Result result = fileScanReq.scanFile();
							printResult(result, true);
						}
					} catch (ScanException ex) {
						System.out.println("Problem encountered! Scanning Failed!! " + ex.getExceptionCode());
					} catch (Exception ex) {
						System.out.println("Problem encountered! Scanning Failed!! ");
					}
				} else {
					FileOutputStream output = null;
					if (streamFileLocal == 1) {
						try {
							if ((scanOutput == null) && (scanMode == 1)) {
								output = new FileOutputStream(defaultResultFile);
							} else {
								output = new FileOutputStream(scanOutput);
							}
							if (isExtendedAPI == 0) {

								ScanEngine scanEngine = ScanEngine.createScanEngine(scanEnginesForScanning);
								StreamScanRequest streamScanReq = scanEngine.createStreamScanRequest(fileForScan, scanFileOriginName, output,
										scPolicy);
								Result result = streamScanReq.scanFile();
								printResult(result, false);
							} else if (isExtendedAPI == 1) {
								ScanEngine scanEngine = ScanEngine.createScanEngine(scanEnginesForScanning);
								StreamScanRequest streamScanReq = scanEngine.createStreamScanRequest(fileForScan, scanFileOriginName, output,
										scPolicy, true);
								Result result = streamScanReq.scanFile();
								printResult(result, true);
							} else {
								ScanEngine scanEngine = ScanEngine.createScanEngine(scanEnginesForScanning);
								StreamScanRequest streamScanReq = scanEngine.createStreamScanRequest(fileForScan, scanFileOriginName, output,
										scPolicy, disableInsightCall, insightOptions);
								Result result = streamScanReq.scanFile();
								printResult(result, true);
							}
							if (output != null) {
								output.close();
							}
						} catch (ScanException ex) {
							if (output != null) {
								try {
									output.close();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
							System.out.println("Problem encountered! Scanning Failed!! " + ex.getExceptionCode());
						} catch (Exception ex) {
							if (output != null) {
								try {
									output.close();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
							System.out.println("Problem encountered! Scanning Failed!! ");
						}
					} else {
						FileInputStream fin = null;
						try {
							int cnt = 0;
							byte[] buff = new byte[512];
							File fp = new File(fileForScan);
							output = null;
							if ((scanOutput == null) && (scanMode == 1)) {
								output = new FileOutputStream(defaultResultFile);
							} else {
								output = new FileOutputStream(scanOutput);
							}
							ScanEngine scanEngine = ScanEngine.createScanEngine(scanEnginesForScanning);
							fin = new FileInputStream(fileForScan);
							StreamScanRequest streamScanReq;
							if (isExtendedAPI == 0)
								streamScanReq = scanEngine.createStreamScanRequest(fileForScan, scanFileOriginName, output, scPolicy);
							else if (isExtendedAPI == 1)
								streamScanReq = scanEngine.createStreamScanRequest(fileForScan, scanFileOriginName, output, scPolicy, true);
							else
								streamScanReq = scanEngine.createStreamScanRequest(fileForScan, scanFileOriginName, output, scPolicy,
										disableInsightCall, insightOptions);

							long bytesToRead = fp.length();
							int buffCapRead = buff.length;
							int bytesRead = 0;

							do {
								if (bytesToRead >= buffCapRead) {
									buffCapRead = buff.length;
								} else {
									buffCapRead = (int) bytesToRead;
								}

								// Refresh data buffer.
								buff = new byte[buffCapRead];

								bytesRead = fin.read(buff, 0, buffCapRead);
								// Send the bytes to Symantec Protection Engine
								streamScanReq.send(buff);
								bytesToRead = bytesToRead - bytesRead;
							} while (bytesToRead > 0);
							if (fin != null) {
								fin.close();
							}
							Result result = streamScanReq.finish();
							if (isExtendedAPI == 0)
								printResult(result, false);
							else
								printResult(result, true);
							if (output != null) {
								output.close();
							}
						} catch (ScanException ex) {
							if (fin != null) {
								try {
									fin.close();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
							if (output != null) {
								try {
									output.close();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
							System.out.println("Problem encountered! Scanning Failed!! " + ex.getExceptionCode());
						} catch (Exception ex) {
							if (fin != null) {
								try {
									fin.close();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
							if (output != null) {
								try {
									output.close();
								} catch (IOException e) {
									// TODO Auto-generated catch block
									e.printStackTrace();
								}
							}
							System.out.println("Problem encountered! Scanning Failed!! ");
						}
					}
				}
			}

		} // End of argument parsing

	} // End of main

} // End of class
