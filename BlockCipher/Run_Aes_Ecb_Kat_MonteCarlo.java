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
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher Modus CBC durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher CBC Mode
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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

public class Run_Aes_Ecb_Kat_MonteCarlo {

    static byte[][] ctCalculated = new byte[250][128];
    static byte[][] ptCalculated = new byte[250][128];

    public static void main(String[] args) throws Exception {
        TeePrintStream ts = new TeePrintStream(System.out, "AES-ECB_KAT_MonteCarlo_Results.txt", true);
        System.setOut(ts);
        System.out.println("AES ECB Known Answer Test (KAT) Monte Carlo");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/Block-Ciphers");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/AESAVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/aes/aesmct.zip");

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version());

        String filenameTest = "";
        boolean verbose = false; // true = print all data, false = print just results
        // statistics
        int nrOfTestfiles = 3;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];

        String[] filenames = { "kat/block_cipher/ecb/ECBMCT128.rsp", "kat/block_cipher/ecb/ECBMCT192.rsp",
        "kat/block_cipher/ecb/ECBMCT256.rsp"};
        for (int algs = 0; algs < filenames.length; algs++) {
            filenameTest = filenames[algs];
            KAT_AES_MonteCarlo.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("\ntesting filename: " + KAT_AES_MonteCarlo.getFilename());
            KAT_AES_MonteCarlo.parse();
            System.out.println("readLines: " + KAT_AES_MonteCarlo.getReadlines());
            System.out.println("header lines: " + KAT_AES_MonteCarlo.header.size());
            // output data
            int counterSize = KAT_AES_MonteCarlo.key.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("Modus: " + KAT_AES_MonteCarlo.modus.get(i)
                        + " key: " + KAT_AES_MonteCarlo.key.get(i)
                        //+ " iv: " + KAT_AES_MonteCarlo.iv.get(i)
                        + " plaintext: " + KAT_AES_MonteCarlo.plaintext.get(i)
                        + " ciphertext: " + KAT_AES_MonteCarlo.ciphertext.get(i)
                );
            }
            // now we are testing the data
            System.out.println("testing the data");

            if (verbose) System.out.println("e start: " + KAT_AES_MonteCarlo.encryptionStart + " e end: " + KAT_AES_MonteCarlo.encryptionEnd
                    + " d start: " + KAT_AES_MonteCarlo.decryptionStart + " d end: " + KAT_AES_MonteCarlo.decryptionEnd);

            // encryption
            // get the testvector inits for encryption
            byte[] KEYinit = hexStringToByteArray(KAT_AES_MonteCarlo.key.get((KAT_AES_MonteCarlo.encryptionStart - 1)));
            byte[] PLAINTEXT = hexStringToByteArray(KAT_AES_MonteCarlo.plaintext.get((KAT_AES_MonteCarlo.encryptionStart - 1)));
            byte[] CIPHERTEXT_exp = hexStringToByteArray(KAT_AES_MonteCarlo.ciphertext.get((KAT_AES_MonteCarlo.encryptionEnd - 1)));
            byte[] CIPHERTEXT_cal = aes_ecb_mct_encrypt(PLAINTEXT, KEYinit);
            if (verbose) System.out.println("CIPHERTEXT_exp: " + bytesToHex(CIPHERTEXT_exp));
            if (verbose) System.out.println("CIPHERTEXT_cal: " + bytesToHex(CIPHERTEXT_cal));
            if (verbose) System.out.println("Encryption OK: " + Arrays.equals(CIPHERTEXT_exp, CIPHERTEXT_cal));
            if (verbose) System.out.println("");
            for (int i = (KAT_AES_MonteCarlo.encryptionStart - 1); i < KAT_AES_MonteCarlo.encryptionEnd; i++) {
                if (verbose) System.out.println("i: " + i + " ct exp: " + KAT_AES_MonteCarlo.ciphertext.get(i)
                        + " ct cal: " + bytesToHex(ctCalculated[i]) + " match: "
                        + Arrays.equals(hexStringToByteArray(KAT_AES_MonteCarlo.ciphertext.get(i)), ctCalculated[i]));
                boolean testPassed = Arrays.equals(ctCalculated[i], hexStringToByteArray (KAT_AES_MonteCarlo.ciphertext.get(i)));
                //if (verbose)
                if (verbose) System.out.println("ENCRYPT testPassed for counter " + i + " : " + testPassed);
                if (testPassed) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;

            // decryption
            // save the allready done tests for offset
            int nrTestPassedEncryption = KAT_AES_MonteCarlo.encryptionEnd - KAT_AES_MonteCarlo.encryptionStart + 1;
            System.out.println("nrTestPassedEncryption: " + nrTestPassedEncryption);
            // get the testvector inits for decryption
            KEYinit = hexStringToByteArray(KAT_AES_MonteCarlo.key.get((KAT_AES_MonteCarlo.decryptionStart - 1)));
            byte[] CIPHERTEXT = hexStringToByteArray(KAT_AES_MonteCarlo.ciphertext.get((KAT_AES_MonteCarlo.decryptionStart - 1)));
            byte[] PLAINTEXT_exp = hexStringToByteArray(KAT_AES_MonteCarlo.plaintext.get((KAT_AES_MonteCarlo.decryptionEnd - 1)));
            byte[] PLAINTEXT_cal = aes_ecb_mct_decrypt(CIPHERTEXT, KEYinit);
            if (verbose) System.out.println("PLAINTEXT_exp: " + bytesToHex(PLAINTEXT_exp));
            if (verbose) System.out.println("PLAINTEXT_cal: " + bytesToHex(PLAINTEXT_cal));
            if (verbose) System.out.println("Decryption OK: " + Arrays.equals(PLAINTEXT_exp, PLAINTEXT_cal));
            if (verbose) System.out.println("");
            for (int i = (KAT_AES_MonteCarlo.decryptionStart - 1); i < KAT_AES_MonteCarlo.decryptionEnd; i++) {
                if (verbose) System.out.println("i: " + i + " pt exp: " + KAT_AES_MonteCarlo.plaintext.get(i)
                        + " pt cal: " + bytesToHex(ptCalculated[i-nrTestPassedEncryption]) + " match: "
                        + Arrays.equals(hexStringToByteArray(KAT_AES_MonteCarlo.plaintext.get(i)), ptCalculated[i-nrTestPassedEncryption]));
                boolean testPassed = Arrays.equals(ptCalculated[i-nrTestPassedEncryption], hexStringToByteArray (KAT_AES_MonteCarlo.plaintext.get(i)));
                //if (verbose)
                if (verbose) System.out.println("DECRYPT testPassed for counter " + i + " : " + testPassed);
                if (testPassed) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrOfTest++;
        }

        System.out.println("\nTest results");
        System.out.println("filename                                tests  passed  failed");
        for (int i = 0; i < nrOfTestfiles; i++) {
            System.out.format("%-39s%5d%8d%8d%n", filename[i], nrTestdata[i], nrTestPassed[i], nrTestFailed[i]);
        }
        ts.close();
    }

    public static byte[] aes_ecb_mct_encrypt(byte[] PLAINTEXT, byte[] KEYinit) throws Exception {
        int i = 0; // outer loop
        int j = 0; // inner loop
        byte[][] KEY = new byte[101][128];
        byte[][] IV = new byte[1001][128];
        byte[][] PT = new byte[1001][128]; // plaintext
        byte[][] CT = new byte[1001][128]; // ciphertext
        // init
        int KEYLENGTH = KEYinit.length * 8;
        KEY[0] = KEYinit;
        PT[0] = PLAINTEXT;
        for (i = 0; i < 100; i++) {
            for (j = 0; j < 1000; j++) {
                CT[j] = aes_ecb_encrypt(PT[j], KEY[i]);
                PT[j + 1] = CT[j];
            }
            j = j - 1; // correction of loop counter
            if (KEYLENGTH == 128) {
                KEY[i + 1] = xor(KEY[i], CT[j]);
            }
            if (KEYLENGTH == 192) {
                KEY[i + 1] = xor192(KEY[i], CT[j - 1], CT[j]);
            }
            if (KEYLENGTH == 256) {
                KEY[i + 1] = xor256(KEY[i], CT[j - 1], CT[j]);
            }
            PT[0] = CT[j];
            ctCalculated[i] = CT[j].clone();
        }
        return CT[j];
    }

    public static byte[] aes_ecb_mct_decrypt(byte[] CIPHERTEXT, byte[] KEYinit) throws Exception {
        int i = 0; // outer loop
        int j = 0; // inner loop
        byte[][] KEY = new byte[101][128];
        byte[][] IV = new byte[1001][128];
        byte[][] CT = new byte[1001][128]; // ciphertext
        byte[][] PT = new byte[1001][128]; // plaintext
        // init
        int KEYLENGTH = KEYinit.length * 8;
        KEY[0] = KEYinit;
        CT[0] = CIPHERTEXT;
        for (i = 0; i < 100; i++) {
            for (j = 0; j < 1000; j++) {
                PT[j] = aes_ecb_decrypt(CT[j], KEY[i]);
                CT[j + 1] = PT[j];
            }
            j = j - 1; // correction of loop counter
            if (KEYLENGTH == 128) {
                KEY[i + 1] = xor(KEY[i], PT[j]);
            }
            if (KEYLENGTH == 192) {
                KEY[i + 1] = xor192(KEY[i], PT[j - 1], PT[j]);
            }
            if (KEYLENGTH == 256) {
                KEY[i + 1] = xor256(KEY[i], PT[j - 1], PT[j]);
            }
            CT[0] = PT[j];
            ptCalculated[i] = PT[j].clone();
        }
        return PT[j];
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

    public static byte[] xor(byte[] a, byte[] b) {
        // nutzung in der mctCbcEncrypt und mctCbcDecrypt methode
        byte[] result = new byte[Math.min(a.length, b.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (((int) a[i]) ^ ((int) b[i]));
        }
        return result;
    }

    public static byte[] xor192(byte[] a, byte[] b, byte[] c) {
        // nutzung in der mctCbcEncrypt und mctCbcDecrypt methode
        // zuerst die letzten 64 bit von b ermitteln
        byte[] resultb = Arrays.copyOfRange(b, b.length - 8, b.length);
        // dann die beiden array b + c zusammenfuegen
        byte[] resultc = new byte[resultb.length + c.length];
        System.arraycopy(resultb, 0, resultc, 0, resultb.length);
        System.arraycopy(c, 0, resultc, resultb.length, c.length);
        // nun das bekannte xoring
        byte[] result = new byte[Math.min(a.length, resultc.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (((int) a[i]) ^ ((int) resultc[i]));
        }
        return result;
    }

    public static byte[] xor256(byte[] a, byte[] b, byte[] c) {
        // nutzung in der mctCbcEncrypt und mctCbcDecrypt methode
        // die beiden array b + c zusammenfuegen
        byte[] resultc = new byte[b.length + c.length];
        System.arraycopy(b, 0, resultc, 0, b.length);
        System.arraycopy(c, 0, resultc, b.length, c.length);
        // nun das bekannte xoring
        byte[] result = new byte[Math.min(a.length, resultc.length)];
        for (int i = 0; i < result.length; i++) {
            result[i] = (byte) (((int) a[i]) ^ ((int) resultc[i]));
        }
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