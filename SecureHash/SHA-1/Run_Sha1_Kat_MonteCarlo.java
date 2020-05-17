package SHA_1;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 17.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) im Monte Carlo Modus für SHA-1 durch
 * Function: performs the Known Answer Test (KAT) in Monte Carlo mode for SHA-1
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/sha-1-kat/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Sha1_Kat_MonteCarlo {
    public static void main(String[] args) throws IOException {
        TeePrintStream ts = new TeePrintStream(System.out, "SHA1_KAT_MonteCarlo_Results.txt", true);
        System.setOut(ts);
        System.out.println("SHA-1 Know Answer Test (KAT) MonteCarlo");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version());

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 1;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        // monte carlo test
        filenameTest = "kat/sha_1/SHA1Monte.rsp";
        KAT_SHA1_MonteCarlo.init(filenameTest);
        filename[nrOfTest] = filenameTest;
        System.out.println("\ntesting filename: " + KAT_SHA1_MonteCarlo.getFilename());
        KAT_SHA1_MonteCarlo.parse();
        System.out.println("readLines: " + KAT_SHA1_MonteCarlo.getReadlines());

        System.out.println("header lines: " + KAT_SHA1_MonteCarlo.header.size());
        // output data
        int counterSize = KAT_SHA1_MonteCarlo.count.size();
        System.out.println("nr of test vectors: " + counterSize);
        for (int i = 0; i < counterSize; i++) {
            if (verbose) System.out.println("seed: " + KAT_SHA1_MonteCarlo.seed.get(i)
                    + " count: " + KAT_SHA1_MonteCarlo.count.get(i)
                    + " md: " + KAT_SHA1_MonteCarlo.md.get(i)
            );
        }

        // now we are testing the data
        System.out.println("\ntesting the data");
        String initSeed = KAT_SHA1_MonteCarlo.seed.get(0);
        for (int j = 0; j < counterSize; j++) {
            // outer loop
            String md1 = initSeed;
            String md2 = initSeed;
            String md3 = initSeed;
            String mdCalculated = "";
            for (int i = 3; i < 1003; i++) {
                // inner loop
                String mdCombined = md1 + md2 + md3;
                mdCalculated = bytesToHex(sha_1(hexStringToByteArray(mdCombined)));
                if (verbose) System.out.println("mdCalculated for i = " + i + " j = " + j + " md = " + mdCalculated);
                md1 = md2;
                md2 = md3;
                md3 = mdCalculated;
            }
            initSeed = mdCalculated;
            boolean testPassed = mdCalculated.contentEquals(KAT_SHA1_MonteCarlo.md.get(j));
            if (verbose)
                System.out.println("md testPassed for counter " + j + " : " + testPassed);
            if (testPassed) {
                nrTestPassed[nrOfTest]++;
            } else {
                nrTestFailed[nrOfTest]++;
            }
        }
        nrTestdata[nrOfTest] = counterSize;

        System.out.println("\nTest results");
        System.out.println("filename                     tests  passed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-28s%5d%8d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestFailed[i]);
        }
        ts.close();
    }

    public static byte[] sha_1 (byte[] input) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch(NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] result = md.digest(input);
        return result;
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
