package Block_Cipher.AES;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 19.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher Modus ECB durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher ECB Mode
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/aes-ecb-kat/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Aes_Ecb_Kat {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        TeePrintStream ts = new TeePrintStream(System.out, "AES-ECB_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("AES ECB Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Block-Ciphers");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/KAT_AES.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version());

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 15;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        String[] filenames = { "kat/block_cipher/ecb/ECBVarKey128.rsp", "kat/block_cipher/ecb/ECBVarTxt128.rsp",
        "kat/block_cipher/ecb/ECBGFSbox128.rsp", "kat/block_cipher/ecb/ECBKeySbox128.rsp",
                "kat/block_cipher/ecb/ECBMMT128.rsp", "kat/block_cipher/ecb/ECBVarKey192.rsp",
                "kat/block_cipher/ecb/ECBVarTxt192.rsp", "kat/block_cipher/ecb/ECBGFSbox192.rsp",
                "kat/block_cipher/ecb/ECBKeySbox192.rsp", "kat/block_cipher/ecb/ECBMMT192.rsp",
                "kat/block_cipher/ecb/ECBVarKey256.rsp", "kat/block_cipher/ecb/ECBVarTxt256.rsp",
                "kat/block_cipher/ecb/ECBGFSbox256.rsp", "kat/block_cipher/ecb/ECBKeySbox256.rsp",
                "kat/block_cipher/ecb/ECBMMT256.rsp"};
        for (int algs = 0; algs < filenames.length; algs++) {
            filenameTest = filenames[algs];
            KAT_AES.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_AES.getFilename());
            KAT_AES.parse();
            System.out.println("readLines: " + KAT_AES.getReadlines());
            System.out.println("header lines: " + KAT_AES.header.size());
            // output data
            int counterSize = KAT_AES.key.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("Modus: " + KAT_AES.modus.get(i)
                        + " key: " + KAT_AES.key.get(i)
                        + " iv: " + KAT_AES.iv.get(i)
                        + " plaintext: " + KAT_AES.plaintext.get(i)
                        + " ciphertext: " + KAT_AES.ciphertext.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");
            for (int i = 0; i < counterSize; i++) {
                if (KAT_AES.modus.get(i) == "ENCRYPT") {
                    String ciphertextCalculated = bytesToHex(aes_ecb_encrypt(hexStringToByteArray(KAT_AES.plaintext.get(i)), hexStringToByteArray(KAT_AES.key.get(i))));
                    boolean testPassed = ciphertextCalculated.contentEquals(KAT_AES.ciphertext.get(i));
                    if (verbose)
                        System.out.println("ENCRYPT testPassed for counter " + i + " : " + testPassed);
                    if (testPassed) {
                        nrTestPassed[nrOfTest]++;
                    } else {
                        nrTestFailed[nrOfTest]++;
                    }
                }
                if (KAT_AES.modus.get(i) == "DECRYPT") {
                    String plainttextCalculated = bytesToHex(aes_ecb_decrypt(hexStringToByteArray(KAT_AES.ciphertext.get(i)), hexStringToByteArray(KAT_AES.key.get(i))));
                    boolean testPassed = plainttextCalculated.contentEquals(KAT_AES.plaintext.get(i));
                    if (verbose)
                        System.out.println("DECRYPT testPassed for counter " + i + " : " + testPassed);
                    if (testPassed) {
                        nrTestPassed[nrOfTest]++;
                    } else {
                        nrTestFailed[nrOfTest]++;
                    }
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        System.out.println("\nTest results");
        System.out.println("filename                                tests  passed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-39s%5d%8d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestFailed[i]);
        }
        ts.close();
    }

    public static byte[] aes_ecb_encrypt(byte[] plaintextByte, byte[] keyByte) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        byte[] ciphertextByte = null;
        SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
        Cipher aesCipherEnc = Cipher.getInstance("AES/ECB/NOPADDING");
        aesCipherEnc.init(Cipher.ENCRYPT_MODE, keySpec);
        ciphertextByte = aesCipherEnc.doFinal(plaintextByte);
        return ciphertextByte;
    }

    public static byte[] aes_ecb_decrypt(byte[] ciphertextByte, byte[] keyByte) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        byte[] decryptedtextByte = null;
        SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
        Cipher aesCipherDec = Cipher.getInstance("AES/ECB/NOPADDING");
        aesCipherDec.init(Cipher.DECRYPT_MODE, keySpec);
        decryptedtextByte = aesCipherDec.doFinal(ciphertextByte);
        return decryptedtextByte;
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
