package Block_Cipher.AES;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 02.06.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher Modus Keywrap durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher Keywrap Mode
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/aes-keywrap-kat/
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
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public class Run_Aes_Keywrap_Kat {
    public static void main(String[] args) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        TeePrintStream ts = new TeePrintStream(System.out, "AES-KEYWRAP_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("AES Keywrap Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/KWVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/kwtestvectors.zip");

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
        String[] filenames = {"kat/block_cipher/keywrap/KW_AE_128.txt", "kat/block_cipher/keywrap/KW_AD_128.txt",
                "kat/block_cipher/keywrap/KW_AE_192.txt", "kat/block_cipher/keywrap/KW_AD_192.txt",
                "kat/block_cipher/keywrap/KW_AE_256.txt", "kat/block_cipher/keywrap/KW_AD_256.txt"},
                modus = {"Encrypt", "Decrypt", "Encrypt", "Decrypt", "Encrypt", "Decrypt"};
        for (int algs = 0; algs < filenames.length; algs++) {
            filenameTest = filenames[algs];
            KAT_AES_KEYWRAP.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_AES_KEYWRAP.getFilename());
            KAT_AES_KEYWRAP.parse();
            System.out.println("readLines: " + KAT_AES_KEYWRAP.getReadlines());
            System.out.println("header lines: " + KAT_AES_KEYWRAP.header.size());
            // output data
            int counterSize = KAT_AES_KEYWRAP.count.size();
            //int counterSize = KAT_AES_KEYWRAP.count.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("Modus: " + KAT_AES_KEYWRAP.modus.get(i)
                        + " key: " + KAT_AES_KEYWRAP.key.get(i)
                        + " plaintext: " + KAT_AES_KEYWRAP.plaintext.get(i)
                        + " ciphertext: " + KAT_AES_KEYWRAP.ciphertext.get(i)
                );
            }

            /*
            System.out.println("pt size: " + KAT_AES_KEYWRAP.plaintext.size()
                    + " ct size: " + KAT_AES_KEYWRAP.ciphertext.size()
                    + " iv size: " + KAT_AES_KEYWRAP.iv.size()
            );
             */

            // now we are testing the data
            System.out.println("testing the data");
            for (int i = 0; i < counterSize; i++) {
                if (modus[algs] == "Encrypt") {
                    String ciphertextCalculated = bytesToHex(aes_keywrap_encrypt(hexStringToByteArray(KAT_AES_KEYWRAP.plaintext.get(i)), hexStringToByteArray(KAT_AES_KEYWRAP.key.get(i))));
                    boolean testPassed = ciphertextCalculated.contentEquals(KAT_AES_KEYWRAP.ciphertext.get(i));
                    if (testPassed == false) {
                        System.out.println("key: " + KAT_AES_KEYWRAP.key.get(i)
                                + " plaintext: " + KAT_AES_KEYWRAP.plaintext.get(i)
                                + " ciphertext: " + KAT_AES_KEYWRAP.ciphertext.get(i)
                                + " ciphertext calc: " + ciphertextCalculated);
                    }
                    if (verbose)
                        System.out.println("ENCRYPT testPassed for counter " + i + " : " + testPassed);
                    if (testPassed) {
                        nrTestPassed[nrOfTest]++;
                    } else {
                        nrTestFailed[nrOfTest]++;
                    }
                }
                if (modus[algs] == "Decrypt") {
/*
                    System.out.println("i: " + i);
                    System.out.println("key: " + KAT_AES_KEYWRAP.key.get(i)
                            + " plaintext: " + KAT_AES_KEYWRAP.plaintext.get(i)
                            + " ciphertext: " + KAT_AES_KEYWRAP.ciphertext.get(i));
                    //+ " plaintext calc: " + plaintextCalculated);
 */
                    String plaintextCalculated = bytesToHex((aes_keywrap_decrypt(hexStringToByteArray(KAT_AES_KEYWRAP.ciphertext.get(i)), hexStringToByteArray(KAT_AES_KEYWRAP.key.get(i)))));
                    boolean testPassed = plaintextCalculated.contentEquals(KAT_AES_KEYWRAP.plaintext.get(i));
                    if (verbose)
                        System.out.println("DECRYPT testPassed for counter " + i + " : " + testPassed);
                    if (testPassed) {
                        nrTestPassed[nrOfTest]++;
                    } else {
                        nrTestFailed[nrOfTest]++;
                        // some tests are expected to fail
                        if (KAT_AES_KEYWRAP.flagFail.get(i) == "true") {
                            nrTestExpectedFailed[nrOfTest]++;
                        }
                    }

                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        System.out.println("\nTest results");
        System.out.println("filename                                     tests  passed  exp.failed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-44s%5d%8d%12d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestExpectedFailed[i], nrTestFailed[i]);
        }
        ts.close();
    }

    public static byte[] aes_keywrap_encrypt(byte[] plaintextByte, byte[] keyByte) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        // der schlüssel wird in die richtige form gebracht
        SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
        // die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
        Cipher aesCipherEnc = Cipher.getInstance("AESWrap");
        aesCipherEnc.init(Cipher.WRAP_MODE, keySpec);
        SecretKeySpec wrapkeySpec = new SecretKeySpec(plaintextByte, "AES");
        return aesCipherEnc.wrap(wrapkeySpec);
    }

    public static byte[] aes_keywrap_decrypt(byte[] ciphertextByte, byte[] keyByte) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException {
        // der schlüssel wird in die richtige form gebracht
        SecretKeySpec keySpec = new SecretKeySpec(keyByte, "AES");
        // die verschlüsselungsroutine wird mit dem gewünschten parameter erstellt
        Cipher aesCipherEnc = Cipher.getInstance("AESWrap");
        aesCipherEnc.init(Cipher.UNWRAP_MODE, keySpec);
        SecretKeySpec wrapkeySpec = new SecretKeySpec(ciphertextByte, "AES");
        byte[] key = new byte[0];
        try {
            key = aesCipherEnc.unwrap(ciphertextByte, "AES", Cipher.SECRET_KEY).getEncoded();
        } catch (InvalidKeyException e) {
            key = "FAIL".getBytes("UTF-8");
        }
        return key;
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
