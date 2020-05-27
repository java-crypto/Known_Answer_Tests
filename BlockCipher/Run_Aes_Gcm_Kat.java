package Block_Cipher.AES;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 27.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher Modus GCM durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher GCM Mode
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/aes-cbc-kat/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Aes_Gcm_Kat {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        TeePrintStream ts = new TeePrintStream(System.out, "AES-GCM_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("AES GCM Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmvs.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/gcmtestvectors.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version());

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 6;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestExpectedFailed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];
        int[] nrTestUnsupported = new int[nrOfTestfiles];

        String[] filenames = {"kat/block_cipher/gcm/gcmEncryptExtIV128.rsp", "kat/block_cipher/gcm/gcmDecrypt128.rsp",
                "kat/block_cipher/gcm/gcmEncryptExtIV192.rsp", "kat/block_cipher/gcm/gcmDecrypt192.rsp",
                "kat/block_cipher/gcm/gcmEncryptExtIV256.rsp", "kat/block_cipher/gcm/gcmDecrypt256.rsp"},
                modus = {"Encrypt", "Decrypt", "Encrypt", "Decrypt", "Encrypt", "Decrypt"};
        for (int algs = 0; algs < filenames.length; algs++) {
            filenameTest = filenames[algs];
            KAT_AES_GCM.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_AES_GCM.getFilename());
            KAT_AES_GCM.parse();
            System.out.println("readLines: " + KAT_AES_GCM.getReadlines());
            System.out.println("header lines: " + KAT_AES_GCM.header.size());
            // output data
            int counterSize = KAT_AES_GCM.tag.size();
            //int counterSize = KAT_AES_GCM.count.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("Modus: " + KAT_AES_GCM.modus.get(i)
                        + " key: " + KAT_AES_GCM.key.get(i)
                        + " iv: " + KAT_AES_GCM.iv.get(i)
                        + " plaintext: " + KAT_AES_GCM.plaintext.get(i)
                        + " ciphertext: " + KAT_AES_GCM.ciphertext.get(i)
                        + " aad: " + KAT_AES_GCM.aad.get(i)
                        + " tag: " + KAT_AES_GCM.tag.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            for (int i = 0; i < counterSize; i++) {
                int taglen = Integer.parseInt(KAT_AES_GCM.taglen.get(i));
                if (taglen < 96) {
                    // unsupported by jce
                    nrTestUnsupported[nrOfTest]++;
                } else {
                    if (modus[algs] == "Encrypt") {
                        String ciphertextCalculated = bytesToHex(aes_gcm_encrypt(hexStringToByteArray(KAT_AES_GCM.plaintext.get(i)), hexStringToByteArray(KAT_AES_GCM.key.get(i)), hexStringToByteArray(KAT_AES_GCM.iv.get(i)), Integer.parseInt(KAT_AES_GCM.taglen.get(i)), hexStringToByteArray(KAT_AES_GCM.aad.get(i))));

                        boolean testPassed = ciphertextCalculated.contentEquals(KAT_AES_GCM.ciphertext.get(i) + KAT_AES_GCM.tag.get(i));
                        if (verbose)
                            System.out.println("ENCRYPT testPassed for counter " + i + " : " + testPassed);
                        if (testPassed) {
                            nrTestPassed[nrOfTest]++;
                        } else {
                            nrTestFailed[nrOfTest]++;
                        }
                    }
                    if (modus[algs] == "Decrypt") {
                        String plaintextCalculated = bytesToHex(aes_gcm_decrypt(hexStringToByteArray((KAT_AES_GCM.ciphertext.get(i) + KAT_AES_GCM.tag.get(i))), hexStringToByteArray(KAT_AES_GCM.key.get(i)), hexStringToByteArray(KAT_AES_GCM.iv.get(i)), Integer.parseInt(KAT_AES_GCM.taglen.get(i)), hexStringToByteArray(KAT_AES_GCM.aad.get(i))));
                        boolean testPassed = plaintextCalculated.contentEquals(KAT_AES_GCM.plaintext.get(i));
                        if (verbose)
                            System.out.println("DECRYPT testPassed for counter " + i + " : " + testPassed);
                        if (testPassed) {
                            nrTestPassed[nrOfTest]++;
                        } else {
                            nrTestFailed[nrOfTest]++;
                            // some tests are expected to fail
                            if (KAT_AES_GCM.flagFail.get(i) == "true") {
                                nrTestExpectedFailed[nrOfTest]++;
                            }
                        }
                    }
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        System.out.println("\nTest results");
        System.out.println("filename                                     tests  passed  exp.failed  failed  unsupported");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-44s%5d%8d%12d%8d%13d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestExpectedFailed[i], nrTestFailed[i], nrTestUnsupported[i]);
        }
        ts.close();
    }

    public static byte[] aes_gcm_encrypt(byte[] plaintextByte, byte[] keyByte, byte[] initvectorByte, int taglen, byte[] aad) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        byte[] ciphertextByte = null;
        SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(taglen, initvectorByte);
        Cipher aesCipherEnc = Cipher.getInstance("AES/GCM/NOPADDING");
        aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
        aesCipherEnc.updateAAD(aad);
        ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
        return ciphertextByte;
    }

    public static byte[] aes_gcm_decrypt(byte[] ciphertextByte, byte[] keyByte, byte[] initvectorByte, int taglen, byte[] aad) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        byte[] plaintextByte = null;
        SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(taglen, initvectorByte);
        Cipher aesCipherDec = Cipher.getInstance("AES/GCM/NOPADDING");
        aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
        aesCipherDec.updateAAD(aad);
        try {
            plaintextByte = aesCipherDec.doFinal(ciphertextByte);
        } catch (AEADBadTagException e) {
            plaintextByte = "FAIL".getBytes("UTF-8");
        }
        return plaintextByte;
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
