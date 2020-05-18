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
 * Funktion: fuehrt den Known Answer Test (KAT) für die SHAKE Familie im Monte Carlos Modus durch
 * Function: performs the Known Answer Test (KAT) for SHAKE family in Monte Carlo Mode
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
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

public class Run_Shake_Kat_MonteCarlo_BC {
    public static void main(String[] args) throws IOException {
        Security.addProvider(new BouncyCastleProvider());
        TeePrintStream ts = new TeePrintStream(System.out, "SHAKE_BC_KAT_MonteCarlo_Results.txt", true);
        System.setOut(ts);
        System.out.println("SHAKE BC Family Known Answer Test (KAT) Monte Carlo Mode");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Secure-Hashing");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/sha3vs.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3/shakebytetestvectors.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version() + " BouncyCastle Version: " + Security.getProvider("BC"));

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 2;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        String[] digests = {"128", "256"},
        filenames = {"kat/shake/SHAKE128Monte.rsp", "kat/shake/SHAKE256Monte.rsp"};
        for (int algs = 0; algs < digests.length; algs++) {
            filenameTest = filenames[algs];
            KAT_SHAKE_MonteCarlo.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_SHAKE_MonteCarlo.getFilename());
            KAT_SHAKE_MonteCarlo.parse();
            System.out.println("readLines: " + KAT_SHAKE_MonteCarlo.getReadlines());
            System.out.println("header lines: " + KAT_SHAKE_MonteCarlo.header.size());
            // output data
            int counterSize = KAT_SHAKE_MonteCarlo.count.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("count: " + KAT_SHAKE_MonteCarlo.count.get(i)
                        + " msg: " + KAT_SHAKE_MonteCarlo.msg
                        + " minimumOutputLength: " + KAT_SHAKE_MonteCarlo.minimumoutputLength
                        + " maximumOutputLength: " + KAT_SHAKE_MonteCarlo.maximumoutputLength
                        + " output: " + KAT_SHAKE_MonteCarlo.output.get(i)
                        + " outputLen: " + KAT_SHAKE_MonteCarlo.outputLen.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            byte[] Output  = hexStringToByteArray(KAT_SHAKE_MonteCarlo.msg);
            int minoutlen = KAT_SHAKE_MonteCarlo.minimumoutputLength;
            int maxoutlen = KAT_SHAKE_MonteCarlo.maximumoutputLength;
            int outputLenBit = (int) ((Math.floor(maxoutlen / 8)) * 8);
            int outputLen = outputLenBit / 8;
            int Range = ((maxoutlen / 8) - (minoutlen / 8) + 1);
            for (int j = 0; j < 100; j++) {
                for (int i = 1; i < 1001; i++) {
                    byte[] MsgI = Arrays.copyOf(Output, (128 / 8));
                    Output = shake_BC(MsgI, Integer.parseInt(digests[algs]), (outputLen));
                    int Rightmost2Byte = Output.length - 2;
                    byte[] OutputRightmost = Arrays.copyOfRange(Output, Rightmost2Byte, Output.length);
                    long value = 0;
                    for (int iv = 0; iv < OutputRightmost.length; iv++)
                    {
                        value = (value << 8) + (OutputRightmost[iv] & 0xff);
                    }
                    outputLen = (int) ((minoutlen / 8) + (value % Range));
                }
                if (verbose) System.out.println("Output 1000/round: " + j + " Output.length: " + Output.length + " data: " + bytesToHex(Output) + " Outputlen: " + outputLen);
                if (Arrays.equals(Output, hexStringToByteArray(KAT_SHAKE_MonteCarlo.output.get(j)))) {
                    if (verbose) System.out.println("md testPassed for counter " + j + " : true");
                    nrTestPassed[nrOfTest]++;
                } else {
                    if (verbose) System.out.println("md testPassed for counter " + j + " : false");
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
