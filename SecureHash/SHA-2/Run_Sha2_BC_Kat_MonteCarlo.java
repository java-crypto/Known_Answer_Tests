package SHA_2;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 17.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) im Monte Carlo Modus  für die SHA-2 Familie durch
 * Function: performs the Known Answer Test (KAT) for SHA-2 family in Monte Carlo mode
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Sha2_BC_Kat_MonteCarlo {
    public static void main(String[] args) throws IOException {
        TeePrintStream ts = new TeePrintStream(System.out, "SHA2_BC_KAT_MonteCarlo_Results.txt", true);
        System.setOut(ts);
        Security.addProvider(new BouncyCastleProvider());
        System.out.println("SHA-2 BC Family Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/shabytetestvectors.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version() + " BouncyCastle Version: " + Security.getProvider("BC"));

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 5;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        String[] digests = {"SHA-256", "SHA-384", "SHA-512", "SHA-512/224", "SHA-512/256"},
                filenames = {"kat/sha_2/SHA256Monte.rsp", "kat/sha_2/SHA384Monte.rsp",
                        "kat/sha_2/SHA512Monte.rsp", "kat/sha_2/SHA512_224Monte.rsp",
                        "kat/sha_2/SHA512_256Monte.rsp"};
        for (int algs = 0; algs < digests.length; algs++) {
            filenameTest = filenames[algs];
            KAT_SHA2_MonteCarlo.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_SHA2_MonteCarlo.getFilename());
            KAT_SHA2_MonteCarlo.parse();
            System.out.println("readLines: " + KAT_SHA2_MonteCarlo.getReadlines());
            System.out.println("header lines: " + KAT_SHA2_MonteCarlo.header.size());
            // output data
            int counterSize = KAT_SHA2_MonteCarlo.count.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("len: " + KAT_SHA2_MonteCarlo.count.get(i)
                        + " count: " + KAT_SHA2_MonteCarlo.count.get(i)
                        + " md: " + KAT_SHA2_MonteCarlo.md.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            String initSeed = KAT_SHA2_MonteCarlo.seed.get(0);
            for (int j = 0; j < counterSize; j++) {
                // outer loop
                String md1 = initSeed;
                String md2 = initSeed;
                String md3 = initSeed;
                String mdCalculated = "";
                for (int i = 3; i < 1003; i++) {
                    // inner loop
                    String mdCombined = md1 + md2 + md3;
                    mdCalculated = bytesToHex(sha_2_BC(hexStringToByteArray(mdCombined), digests[algs]));
                    if (verbose) System.out.println("mdCalculated for i = " + i + " j = " + j + " md = " + mdCalculated);
                    md1 = md2;
                    md2 = md3;
                    md3 = mdCalculated;
                }
                initSeed = mdCalculated;
                boolean testPassed = mdCalculated.contentEquals(KAT_SHA2_MonteCarlo.md.get(j));
                if (verbose)
                    System.out.println("md testPassed for counter " + j + " : " + testPassed);
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
        System.out.println("filename                         tests  passed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-32s%5d%8d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestFailed[i]);
        }
        ts.close();
    }

    public static byte[] sha_2_BC(byte[] input, String algorithm) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(algorithm, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
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
