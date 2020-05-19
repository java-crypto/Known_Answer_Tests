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
 * Funktion: fuehrt den Known Answer Test (KAT) für AES Blockcipher durch
 * Function: performs the Known Answer Test (KAT) for AES blockcipher Mode
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

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class KAT_AES_MonteCarlo {
    static List<String> header = new ArrayList<String>();
    static List<String> modus = new ArrayList<String>();
    static List<String> count = new ArrayList<String>();
    static List<String> key = new ArrayList<String>();
    static List<String> iv = new ArrayList<String>();
    static List<String> plaintext = new ArrayList<String>();
    static List<String> ciphertext = new ArrayList<String>();
    static String modusFixed = "";
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;
    public static int encryptionStart = 0;
    public static int encryptionEnd = 0;
    public static int decryptionStart = 0;
    public static int decryptionEnd = 0;
    public static int counter = 0;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        encryptionStart = 0;
        encryptionEnd = 0;
        decryptionStart = 0;
        decryptionEnd = 0;
        counter = 0;
        header.clear();
        modus.clear();
        key.clear();
        count.clear();
        iv.clear();
        plaintext.clear();
        ciphertext.clear();
        headerPhase = true;
    }

    static String getFilename() {
        return filename;
    }

    static int getReadlines() {
        return readLines;
    }

    static boolean parse() {
        int zeilennummer = 0;
        try (BufferedReader br = Files.newBufferedReader(Paths.get(filename))) {
            // read line by line
            String line;
            while ((line = br.readLine()) != null) {
                zeilennummer++;
                analyzeLine(line);
            }
        } catch (IOException e) {
            System.err.format("IOException: %s%n", e);
        } // auto closure
        return true;
    }

    static void analyzeLine(String line) {
        readLines++;
        // headerPhase ?
        if (headerPhase) {
            if (line.startsWith("#")) {
                header.add(line);
            } else {
                // headerPhase ends
                headerPhase = false;
            }
        }
        if (!headerPhase) {
            // analyzing data
            if (line.equals("[ENCRYPT]")) {
                // [ENCRYPT]
                modusFixed = "ENCRYPT";
            }
            if (line.equals("[DECRYPT]")) {
                // [DECRYPT]
                modusFixed = "DECRYPT";
            }
            if (line.startsWith("COUNT")) {
                // COUNT = 0
                count.add(line.replace("COUNT = ", ""));
                counter++;
            }
            if (line.startsWith("KEY")) {
                // KEY = 80000000000000000000000000000000
                key.add(line.replace("KEY = ", ""));
            }
            if (line.startsWith("IV")) {
                // IV = 00000000000000000000000000000000
                iv.add(line.replace("IV = ", ""));
            }
            if (line.startsWith("PLAINTEXT")) {
                // PLAINTEXT = 00000000000000000000000000000000
                plaintext.add(line.replace("PLAINTEXT = ", ""));
                // first and last encrypt  plaintext
                if (modusFixed == "ENCRYPT") {
                    if (encryptionStart == 0) { // not saved
                        encryptionStart = counter;
                    }
                    encryptionEnd = counter;
                }
                // first and last decrypt  plaintext
                if (modusFixed == "DECRYPT") {
                    if (decryptionStart == 0) { // not saved
                        decryptionStart = counter;
                    }
                    decryptionEnd = counter;
                }
            }
            if (line.startsWith("CIPHERTEXT")) {
                // CIPHERTEXT = 0edd33d3c621e546455bd8ba1418bec8
                ciphertext.add(line.replace("CIPHERTEXT = ", ""));
                modus.add(modusFixed);
            }
        }
    }
}


