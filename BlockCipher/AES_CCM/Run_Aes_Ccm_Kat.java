package Block_Cipher.AES.CCM;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 23.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher Modus CCM durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher CCM Mode
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/aes-ccm-kat/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import org.bouncycastle.jcajce.spec.AEADParameterSpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;

public class Run_Aes_Ccm_Kat {

    static boolean verbose = false; // true = output all lines, false = output just the statistics

    public static void main(String[] args) throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IOException, BadPaddingException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException {
        TeePrintStream ts = new TeePrintStream(System.out, "AES-CCM_BC_KAT_Results.txt", true);
        System.setOut(ts);
        System.out.println("AES CCM BC Known Answer Test (KAT)");
        System.out.println("for information see: https://csrc.nist.gov/Projects/cryptographic-algorithm-validation-program/CAVP-TESTING-BLOCK-CIPHER-MODES");
        System.out.println("for tests see: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/CCMVS.pdf");
        System.out.println("get the testfiles: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/mac/ccmtestvectors.zip");
        Security.addProvider(new BouncyCastleProvider());

        System.out.println("\nTest on " + getActualDate() + " with Java version: " + Runtime.version() + " BouncyCastle Version: " + Security.getProvider("BC") + "\n");

        // statistics
        int nrOfTestfiles = 15;
        int nrOfTest = 0;
        String[] filename = new String[nrOfTestfiles];
        int[] nrTestdata = new int[nrOfTestfiles];
        int[] nrTestPassed = new int[nrOfTestfiles];
        int[] nrTestFailed = new int[nrOfTestfiles];
        String filenameTest;

        String[] filenames = {"kat/block_cipher/ccm/VTT128.rsp", "kat/block_cipher/ccm/VTT192.rsp",
                "kat/block_cipher/ccm/VTT256.rsp"};
        for (int algs = 0; algs < filenames.length; algs++) {
            filenameTest = filenames[algs];
            KAT_CCM_VTT.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("testing filename: " + KAT_CCM_VTT.getFilename());
            System.out.println("filename:  " + KAT_CCM_VTT.getFilename());
            KAT_CCM_VTT.parse();
            System.out.println("readLines: " + KAT_CCM_VTT.getReadlines());
            System.out.println("header lines: " + KAT_CCM_VTT.header.size());
            // output data
            int counterSize = KAT_CCM_VTT.counter.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                if (verbose) System.out.println("counter: " + KAT_CCM_VTT.counter.get(i)
                        + " tLen: " + KAT_CCM_VTT.tLen.get(i)
                        + " key: " + KAT_CCM_VTT.key.get(i)
                        + " nonce: " + KAT_CCM_VTT.nonce.get(i)
                        + " adata: " + KAT_CCM_VTT.adata.get(i)
                        + " payload: " + KAT_CCM_VTT.payload.get(i)
                        + " ct: " + KAT_CCM_VTT.ct.get(i)
                );
            }

            // now we are testing the data
            System.out.println("\ntesting");
            for (int i = 0; i < counterSize; i++) {
                String ctCalculated = encryptWithCcmBc(KAT_CCM_VTT.tLen.get(i), KAT_CCM_VTT.key.get(i), KAT_CCM_VTT.nonce.get(i), KAT_CCM_VTT.adata.get(i), KAT_CCM_VTT.payload.get(i));
                if (verbose)
                    System.out.println("encryption testPassed for counter " + i + " : " + ctCalculated.contentEquals(KAT_CCM_VTT.ct.get(i)));
                // inofficial test
                String payloadCalculated = decryptWithCcmBc(KAT_CCM_VTT.tLen.get(i), KAT_CCM_VTT.key.get(i), KAT_CCM_VTT.nonce.get(i), KAT_CCM_VTT.adata.get(i), ctCalculated);
                if (verbose)
                    System.out.println("decryption testPassed for counter " + i + " : " + payloadCalculated.contentEquals(KAT_CCM_VTT.payload.get(i)));
                if (payloadCalculated.contentEquals(KAT_CCM_VTT.payload.get(i))) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        // new file set
        String[] filenamesVPT = {"kat/block_cipher/ccm/VPT128.rsp", "kat/block_cipher/ccm/VPT192.rsp",
                "kat/block_cipher/ccm/VPT256.rsp"};
        for (int algs = 0; algs < filenamesVPT.length; algs++) {
            filenameTest = filenamesVPT[algs];
            KAT_CCM_VPT.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("testing filename: " + KAT_CCM_VPT.getFilename());
            KAT_CCM_VPT.parse();
            int counterSize = KAT_CCM_VPT.counter.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                String ctCalculated = encryptWithCcmBc(KAT_CCM_VPT.tLen.get(i), KAT_CCM_VPT.key.get(i), KAT_CCM_VPT.nonce.get(i), KAT_CCM_VPT.adata.get(i), KAT_CCM_VPT.payload.get(i));
                if (verbose)
                    System.out.println("encryption testPassed for counter " + i + " : " + ctCalculated.contentEquals(KAT_CCM_VPT.ct.get(i)));
                String payloadCalculated = decryptWithCcmBc(KAT_CCM_VPT.tLen.get(i), KAT_CCM_VPT.key.get(i), KAT_CCM_VPT.nonce.get(i), KAT_CCM_VPT.adata.get(i), ctCalculated);
                if (verbose)
                    System.out.println("decryption testPassed for counter " + i + " : " + payloadCalculated.contentEquals(KAT_CCM_VPT.payload.get(i)));
                if (payloadCalculated.contentEquals(KAT_CCM_VPT.payload.get(i))) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        // new file set
        String[] filenamesVNT = {"kat/block_cipher/ccm/VNT128.rsp", "kat/block_cipher/ccm/VNT192.rsp",
                "kat/block_cipher/ccm/VNT256.rsp"};
        for (int algs = 0; algs < filenamesVNT.length; algs++) {
            filenameTest = filenamesVNT[algs];
            KAT_CCM_VNT.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("testing filename: " + KAT_CCM_VNT.getFilename());
            KAT_CCM_VNT.parse();
            int counterSize = KAT_CCM_VNT.counter.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                String ctCalculated = encryptWithCcmBc(KAT_CCM_VNT.tLen.get(i), KAT_CCM_VNT.key.get(i), KAT_CCM_VNT.nonce.get(i), KAT_CCM_VNT.adata.get(i), KAT_CCM_VNT.payload.get(i));
                if (verbose)
                    System.out.println("encryption testPassed for counter " + i + " : " + ctCalculated.contentEquals(KAT_CCM_VNT.ct.get(i)));
                // inofficial test
                String payloadCalculated = decryptWithCcmBc(KAT_CCM_VNT.tLen.get(i), KAT_CCM_VNT.key.get(i), KAT_CCM_VNT.nonce.get(i), KAT_CCM_VNT.adata.get(i), ctCalculated);
                if (verbose)
                    System.out.println("decryption testPassed for counter " + i + " : " + payloadCalculated.contentEquals(KAT_CCM_VNT.payload.get(i)));
                if (payloadCalculated.contentEquals(KAT_CCM_VNT.payload.get(i))) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        // new file set
        String[] filenamesVADT = {"kat/block_cipher/ccm/VADT128.rsp", "kat/block_cipher/ccm/VADT192.rsp",
                "kat/block_cipher/ccm/VADT256.rsp"};
        for (int algs = 0; algs < filenamesVADT.length; algs++) {
            filenameTest = filenamesVADT[algs];
            KAT_CCM_VADT.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("testing filename: " + KAT_CCM_VADT.getFilename());
            KAT_CCM_VADT.parse();
            int counterSize = KAT_CCM_VADT.counter.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                String ctCalculated = encryptWithCcmBc(KAT_CCM_VADT.tLen.get(i), KAT_CCM_VADT.key.get(i), KAT_CCM_VADT.nonce.get(i), KAT_CCM_VADT.adata.get(i), KAT_CCM_VADT.payload.get(i));
                if (verbose)
                    System.out.println("encryption testPassed for counter " + i + " : " + ctCalculated.contentEquals(KAT_CCM_VADT.ct.get(i)));
                // inofficial test
                String payloadCalculated = decryptWithCcmBc(KAT_CCM_VADT.tLen.get(i), KAT_CCM_VADT.key.get(i), KAT_CCM_VADT.nonce.get(i), KAT_CCM_VADT.adata.get(i), ctCalculated);
                if (verbose)
                    System.out.println("decryption testPassed for counter " + i + " : " + payloadCalculated.contentEquals(KAT_CCM_VADT.payload.get(i)));
                if (payloadCalculated.contentEquals(KAT_CCM_VADT.payload.get(i))) {
                    nrTestPassed[nrOfTest]++;
                } else {
                    nrTestFailed[nrOfTest]++;
                }
            }
            nrTestdata[nrOfTest] = counterSize;
            nrOfTest++;
        }

        // new file set
        String[] filenamesDVPT = {"kat/block_cipher/ccm/DVPT128.rsp", "kat/block_cipher/ccm/DVPT192.rsp",
                "kat/block_cipher/ccm/DVPT256.rsp"};
        for (int algs = 0; algs < filenamesDVPT.length; algs++) {
            filenameTest = filenamesDVPT[algs];
            // official decryption
            KAT_CCM_DVPT.init(filenameTest);
            filename[nrOfTest] = filenameTest;
            System.out.println("testing filename: " + KAT_CCM_DVPT.getFilename());
            KAT_CCM_DVPT.parse();
            int counterSize = KAT_CCM_DVPT.counter.size();
            System.out.println("nr of test vectors: " + counterSize);
            for (int i = 0; i < counterSize; i++) {
                String payloadCalculated = decryptWithCcmBc(KAT_CCM_DVPT.tLen.get(i), KAT_CCM_DVPT.key.get(i), KAT_CCM_DVPT.nonce.get(i), KAT_CCM_DVPT.adata.get(i), KAT_CCM_DVPT.ct.get(i));
                boolean payloadCalculatedMatch = payloadCalculated.contentEquals(KAT_CCM_DVPT.payload.get(i));
                boolean payloadExpectedMatch = false;
                if (KAT_CCM_DVPT.result.get(i) == "Pass") payloadExpectedMatch = true;
                if (verbose)
                    System.out.println("decryption testPassed for counter " + i + " : " + payloadCalculatedMatch
                            + " expected: " + payloadExpectedMatch
                            + " testpassed: " + (payloadExpectedMatch == payloadCalculatedMatch));
                // inofficial test for passed
                if (payloadCalculatedMatch) {
                    String ctCalculated = encryptWithCcmBc(KAT_CCM_DVPT.tLen.get(i), KAT_CCM_DVPT.key.get(i), KAT_CCM_DVPT.nonce.get(i), KAT_CCM_DVPT.adata.get(i), KAT_CCM_DVPT.payload.get(i));
                    if (verbose)
                        System.out.println("encryption testPassed for counter " + i + " : " + ctCalculated.contentEquals(KAT_CCM_DVPT.ct.get(i)));
                    if (payloadCalculated.contentEquals(KAT_CCM_DVPT.payload.get(i))) {
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

    static String encryptWithCcmBc(String tLenString, String key, String nonce, String aData, String payload) throws
            NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int tLen = Integer.parseInt(tLenString);
        byte[] payloadData;
        byte[] aadData;
        byte[] nonceData; // 13 = maximal for iv = nonce
        byte[] keyData;
        payloadData = hexStringToByteArray(payload);
        aadData = hexStringToByteArray(aData);
        nonceData = hexStringToByteArray(nonce);
        keyData = hexStringToByteArray(key);
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec((tLen * 8), nonceData);
        SecretKey secretKey = new SecretKeySpec(keyData, 0, keyData.length, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        cipher.updateAAD(aadData);
        return bytesToHex(cipher.doFinal(payloadData));
    }

    public static String decryptWithCcmBc(String tLenString, String key, String nonce, String aData, String ciphertext) throws
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        int tLen = Integer.parseInt(tLenString);
        byte[] aadData;
        byte[] nonceData; // 13 = maximal for iv = nonce
        byte[] keyData;
        byte[] cipherData;
        cipherData = hexStringToByteArray(ciphertext);
        aadData = hexStringToByteArray(aData);
        nonceData = hexStringToByteArray(nonce);
        keyData = hexStringToByteArray(key);
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        AEADParameterSpec spec = new AEADParameterSpec(nonceData, (tLen * 8), aadData);
        SecretKey secretKey = new SecretKeySpec(keyData, 0, keyData.length, "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
        byte[] decrypttext = null;
        try {
            decrypttext = cipher.doFinal(cipherData);
        } catch (AEADBadTagException e) {
            decrypttext = new byte[1];
        }
        return bytesToHex(decrypttext);
    }


    static boolean encryptWithCcmBcOrg(int counter, int aLen, int pLen, int nLen, int tLen, int kLen, int cLen, String key, String nonce, String aData, String payload, String ct) throws
            NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        // Generating IV / nonce
        //byte iv[] = new byte[IV_SIZE];
        byte[] payloadData = new byte[pLen];
        byte[] aadData = new byte[aLen];
        byte[] nonceData = new byte[nLen]; // 13 = maximal for iv = nonce
        byte[] tag = new byte[tLen * 8];
        byte[] keyData = new byte[kLen];
        byte[] cipherData = new byte[cLen];

        payloadData = hexStringToByteArray(payload);
        aadData = hexStringToByteArray(aData);
        nonceData = hexStringToByteArray(nonce);
        keyData = hexStringToByteArray(key);
        cipherData = hexStringToByteArray(ct);
        //System.out.println("nonce           : " + bytesToHex(nonceData));

        //SecureRandom secRandom = new SecureRandom() ;
        //secRandom.nextBytes(nonceData); // SecureRandom initialized using self-seeding
        Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
        GCMParameterSpec spec = new GCMParameterSpec((tLen * 8), nonceData);
        SecretKey secretKey = new SecretKeySpec(keyData, 0, keyData.length, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);
        cipher.updateAAD(aadData);
        byte[] ciphertext = cipher.doFinal(payloadData);
        System.out.println("payloadData     : " + bytesToHex(payloadData));
        System.out.println("aadData         : " + bytesToHex(aadData));
        System.out.println("nonce           : " + bytesToHex(nonceData));
        System.out.println("keyData         : " + bytesToHex(keyData));
        System.out.println("ciphertext      : " + bytesToHex(ciphertext));
        System.out.println("cipherData      : " + bytesToHex(cipherData));

        return Arrays.equals(ciphertext, cipherData);
    }


    public static void decryptWithCcmBc3Org(String filenameEnc, String filenameDec, byte[] key, byte[] aad) throws IOException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException,
            IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
        try (FileInputStream in = new FileInputStream(filenameEnc);
             FileOutputStream out = new FileOutputStream(filenameDec)) {
            byte[] ibuf = new byte[1024];
            int len;
            //byte[] nonce = new byte[GCM_NONCE_LENGTH];
            byte[] nonce = new byte[12];
            in.read(nonce);
            Cipher cipher = Cipher.getInstance("AES/CCM/NoPadding", "BC");
            //SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            AEADParameterSpec spec = new AEADParameterSpec(nonce, 128, aad);
            SecretKey secretKey = new SecretKeySpec(key, 0, key.length, "AES");
            //GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, spec);
            while ((len = in.read(ibuf)) != -1) {
                byte[] obuf = cipher.update(ibuf, 0, len);
                if (obuf != null)
                    out.write(obuf);
            }
            byte[] obuf = cipher.doFinal();
            if (obuf != null)
                out.write(obuf);
        }
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
