package SHAKE;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 18.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für die SHAKE Familie durch
 * Function: performs the Known Answer Test (KAT) for SHAKE family
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/shake-kat/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.io.IOException;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Shake_Kat_BC {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        TeePrintStream ts = new TeePrintStream(System.out, "SHAKE_BC_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("SHAKE BC Family Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version() + " BouncyCastle Version: " + Security.getProvider("BC"));

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 6;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        String[] digests = {"128", "128", "256", "256"},
                filenames = {"kat/shake/SHAKE128ShortMsg.rsp", "kat/shake/SHAKE128LongMsg.rsp",
                        "kat/shake/SHAKE256ShortMsg.rsp", "kat/shake/SHAKE256LongMsg.rsp"
                };
        for (int algs = 0; algs < digests.length; algs++) {
            filenameTest = filenames[algs];
            KAT_SHAKE.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_SHAKE.getFilename());
            KAT_SHAKE.parse();
            System.out.println("readLines: " + KAT_SHAKE.getReadlines());
            System.out.println("header lines: " + KAT_SHAKE.header.size());
            // output data
            int counterSize = KAT_SHAKE.len.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("len: " + KAT_SHAKE.len.get(i)
                        + " msg: " + KAT_SHAKE.msg.get(i)
                        + " output: " + KAT_SHAKE.output.get(i)
                        + " outputLen: " + KAT_SHAKE.outputLen.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            for (int i = 0; i < counterSize; i++) {
                String mdCalculated = bytesToHex(shake_BC(hexStringToByteArray(KAT_SHAKE.msg.get(i)), Integer.parseInt(digests[algs]), (KAT_SHAKE.outputLen.get(i) / 8)));
                boolean testPassed = mdCalculated.contentEquals(KAT_SHAKE.output.get(i));
                if (verbose) {
                    System.out.println("mdCalculated: " + mdCalculated);
                    System.out.println("md testPassed for counter " + i + " : " + testPassed);
                }
                if (testPassed) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        // variable output
        String[] digestsV = {"128", "256"},
                filenamesV = {"kat/shake/SHAKE128VariableOut.rsp",
                        "kat/shake/SHAKE256VariableOut.rsp",
                };
        for (int algs = 0; algs < digestsV.length; algs++) {
            filenameTest = filenamesV[algs];
            KAT_SHAKE_VariableOut.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_SHAKE_VariableOut.getFilename());
            KAT_SHAKE_VariableOut.parse();
            System.out.println("readLines: " + KAT_SHAKE_VariableOut.getReadlines());
            System.out.println("header lines: " + KAT_SHAKE_VariableOut.header.size());
            // output data
            int counterSize = KAT_SHAKE_VariableOut.count.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("count: " + KAT_SHAKE_VariableOut.count.get(i)
                        + " msg: " + KAT_SHAKE_VariableOut.msg.get(i)
                        + " output: " + KAT_SHAKE_VariableOut.output.get(i)
                        + " outputLen: " + KAT_SHAKE_VariableOut.outputLen.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            for (int i = 0; i < counterSize; i++) {
                String mdCalculated = bytesToHex(shake_BC(hexStringToByteArray(KAT_SHAKE_VariableOut.msg.get(i)), Integer.parseInt(digestsV[algs]), (Integer.parseInt(KAT_SHAKE_VariableOut.outputLen.get(i)) / 8)));
                boolean testPassed = mdCalculated.contentEquals(KAT_SHAKE_VariableOut.output.get(i));
                if (verbose) {
                    System.out.println("mdCalculated: " + mdCalculated);
                    System.out.println("md testPassed for counter " + i + " : " + testPassed);
                }
                if (testPassed) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        System.out.println("\nTest results");
        System.out.println("filename                            tests  passed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-35s%5d%8d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestFailed[i]);
        }
        ts.close();
    }

    public static byte[] shake_BC(byte[] input, int bitlength, int outputLength) {
        SHAKEDigest shakeDigest = new SHAKEDigest(bitlength);
        byte[] output = new byte[outputLength];
        shakeDigest.update(input, 0, input.length);
        shakeDigest.doOutput(output, 0, outputLength / 2);
        shakeDigest.doFinal(output, outputLength / 2, output.length - outputLength / 2);
        return output;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuffer result = new StringBuffer();
        for (byte b : bytes) result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }

    private static String getActualDate() {
        // provides the actual date and time in this format dd-MM-yyyy_HH-mm-ss e.g. 16-03-2020_10-27-15
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");
        LocalDateTime today = LocalDateTime.now();
        return formatter.format(today);
    }
}
