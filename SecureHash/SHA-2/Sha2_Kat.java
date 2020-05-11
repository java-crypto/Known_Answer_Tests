package SHA_2;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 10.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für die SHA-2 Familie durch
 * Function: performs the Known Answer Test (KAT) for SHA-2 family
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/sha-2-kat/
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

public class Sha2_Kat {
    public static void main(String[] args) throws IOException {
        TeePrintStream ts = new TeePrintStream(System.out, "SHA2_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("SHA-2 Family Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing");
        System.out.println("for tests see: http://csrc.nist.gov/groups/STM/cavp/documents/shs/SHAVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip");

        System.out.println("\nTest with Java version: " + Runtime.version() + " on " + getActualDate());

        String filenameTest = "";
        boolean verbose = true; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 10;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        String[] digests = {"SHA-256", "SHA-256", "SHA-384", "SHA-384", "SHA-512", "SHA-512", "SHA-512/224", "SHA-512/224", "SHA-512/256", "SHA-512/256"},
                filenames = {"kat/sha_2/SHA256ShortMsg.rsp", "kat/sha_2/SHA256LongMsg.rsp",
                        "kat/sha_2/SHA384ShortMsg.rsp", "kat/sha_2/SHA384LongMsg.rsp",
                        "kat/sha_2/SHA512ShortMsg.rsp", "kat/sha_2/SHA512LongMsg.rsp",
                        "kat/sha_2/SHA512_224ShortMsg.rsp", "kat/sha_2/SHA512_224LongMsg.rsp",
                        "kat/sha_2/SHA512_256ShortMsg.rsp", "kat/sha_2/SHA512_256LongMsg.rsp"};
        for (int algs = 0; algs < digests.length; algs++) {
            filenameTest = filenames[algs];
            KAT_SHA2.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_SHA2.getFilename());
            KAT_SHA2.parse();
            System.out.println("readLines: " + KAT_SHA2.getReadlines());
            System.out.println("header lines: " + KAT_SHA2.header.size());
            // output data
            int counterSize = KAT_SHA2.len.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("len: " + KAT_SHA2.len.get(i)
                        + " msg: " + KAT_SHA2.msg.get(i)
                        + " md: " + KAT_SHA2.md.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            for (int i = 0; i < counterSize; i++) {
                String mdCalculated = bytesToHex(sha_2(hexStringToByteArray(KAT_SHA2.msg.get(i)), digests[algs]));
                boolean testPassed = mdCalculated.contentEquals(KAT_SHA2.md.get(i));
                if (verbose)
                    System.out.println("md testPassed for counter " + i + " : " + testPassed);
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
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.print("filename " + filename[i]
                    + " nr of tests " + nrTestdata[i]
                    + " nr of tests passed " + nrTestPassed[i]
                    + " nr of tests failed " + nrTestFailed[i]);
            System.out.println();
        }
    }

    public static byte[] sha_2(byte[] input, String algorithm) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException e) {
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
