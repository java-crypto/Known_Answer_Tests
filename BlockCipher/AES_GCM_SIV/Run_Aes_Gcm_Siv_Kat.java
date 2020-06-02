package Block_Cipher.AES.GCM_SIV;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 02.06.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher Modus GCM-SIV durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher GCM-SIV Mode
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/aes-gcm-siv-kat/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 * Sie benötigen eine externe Library fue die Nutzung des Programms /
 * You need an external library to use this program:
 * https://gitlab.com/tlchiu40209/easyaes-gcm-siv
 * EasyAES is available under Licence: Apache License Version 2.0, January 2004
 */

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Aes_Gcm_Siv_Kat {

    static boolean verbose = false; // true = output all lines, false = output just the statistics

    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        TeePrintStream ts = new TeePrintStream(System.out, "AES-GCM_SIV_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("AES GCM SIV Known Answer Test (KAT)");
        System.out.println("for information see: https://tools.ietf.org/html/rfc8452");
        System.out.println("for tests see: https://tools.ietf.org/html/rfc8452");
        System.out.println("get the testfiles: https://tools.ietf.org/html/rfc8452");
        System.out.println("get EasyAES here: https://gitlab.com/tlchiu40209/easyaes-gcm-siv");
        System.out.println("EasyAES is available under Licence: Apache License Version 2.0, January 2004");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version() + "\n");

        // statistics
        int nrOfTestfiles = 3;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];
        int[] nrTestEncryptionPassed = new int[nrOfTestfiles];
        int[] nrTestEncryptionFailed = new int[nrOfTestfiles];
        int[] nrTestDecryptionPassed = new int[nrOfTestfiles];
        int[] nrTestDecryptionFailed = new int[nrOfTestfiles];
        String filenameTest;

        String[] filenames = {"kat/block_cipher/gcm_siv/AEAD_AES_128_GCM_SIV.txt", "kat/block_cipher/gcm_siv/AEAD_AES_256_GCM_SIV.txt",
        "kat/block_cipher/gcm_siv/AEAD_AES_256_GCM_SIV_KEYWRAP.txt"};
        for (int algs = 0; algs < filenames.length; algs++) {
            filenameTest = filenames[algs];
            KAT_GCM_SIV.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("testing filename: " + KAT_GCM_SIV.getFilename());
            System.out.println("filename:  " + KAT_GCM_SIV.getFilename());
            KAT_GCM_SIV.parse();
            System.out.println("readLines: " + KAT_GCM_SIV.getReadlines());
            System.out.println("header lines: " + KAT_GCM_SIV.header.size());
            // output data
            int counterSize = KAT_GCM_SIV.plaintext.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("key: " + KAT_GCM_SIV.key.get(i)
                        + " nonce: " + KAT_GCM_SIV.nonce.get(i)
                        + " adata: " + KAT_GCM_SIV.adata.get(i)
                        + " plaintext: " + KAT_GCM_SIV.plaintext.get(i)
                        + " result: " + KAT_GCM_SIV.result.get(i)
                );
            }

            // now we are testing the data
            System.out.println("testing encryption & decryption");
            for (int i = 0; i < counterSize; i++) {
                EasyAES eaes = new EasyAES(hexStringToByteArray(KAT_GCM_SIV.key.get(i)), hexStringToByteArray(KAT_GCM_SIV.nonce.get(i)), hexStringToByteArray(KAT_GCM_SIV.adata.get(i)));
                byte[] ciphertext = eaes.SIV_encrypt(hexStringToByteArray(KAT_GCM_SIV.plaintext.get(i)));
                byte[] decrypttext = eaes.SIV_decrypt(hexStringToByteArray(KAT_GCM_SIV.result.get(i)));
                String resultEncryptionCalculated = bytesToHex(ciphertext);
                String resultDecryptionCalculated = bytesToHex(decrypttext);
                if (resultEncryptionCalculated.contentEquals(KAT_GCM_SIV.result.get(i)) == true) {
                    nrTestPassed[nrOfTest]++;
                    nrTestEncryptionPassed[nrOfTest]++;
                } else
                {
                    nrTestFailed[nrOfTest]++;
                    nrTestEncryptionFailed[nrOfTest]++;
                }
                if (resultDecryptionCalculated.contentEquals(KAT_GCM_SIV.plaintext.get(i)) == true) {
                    nrTestPassed[nrOfTest]++;
                    nrTestDecryptionPassed[nrOfTest]++;
                } else
                {
                    nrTestFailed[nrOfTest]++;
                    nrTestDecryptionFailed[nrOfTest]++;
                }
                if (verbose) {
                    System.out.println("encryption testPassed for counter " + i + " : " + resultEncryptionCalculated.contentEquals(KAT_GCM_SIV.result.get(i)));
                    System.out.println("decryption testPassed for counter " + i + " : " + resultDecryptionCalculated.contentEquals(KAT_GCM_SIV.plaintext.get(i)));
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        System.out.println("\nTest results");
        System.out.println("filename                                                  tests  passed  failed  Enc passed  failed  Dec passed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-57s%5d%8d%8d%12d%8d%12d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestFailed[i],
                    nrTestEncryptionPassed[i], nrTestEncryptionFailed[i], nrTestDecryptionPassed[i], nrTestDecryptionFailed[i]);
        }
        ts.close();
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
