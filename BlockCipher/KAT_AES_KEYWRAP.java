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

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class KAT_AES_KEYWRAP {
    static List<String> header = new ArrayList<String>();
    static List<String> modus = new ArrayList<String>();
    static List<String> count = new ArrayList<String>();
    static List<String> key = new ArrayList<String>();
    static List<String> plaintext = new ArrayList<String>();
    static List<String> ciphertext = new ArrayList<String>();
    static List<String> flagFail = new ArrayList<String>();
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;
    private static int countersize = 0;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        modus.clear();
        key.clear();
        count.clear();
        plaintext.clear();
        ciphertext.clear();
        flagFail.clear();
        headerPhase = true;
        countersize = 0;
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
            if (line.startsWith("COUNT")) {
                // COUNT = 0
                count.add(line.replace("COUNT = ", ""));
                countersize++;
                flagFail.add("false");
            }
            if (line.startsWith("K =")) {
                // K = 7575da3a93607cc2bfd8cec7aadfd9a6
                key.add(line.replace("K = ", ""));
            }
            if (line.startsWith("P")) {
                // P = 42136d3c384a3eeac95a066fd28fed3f
                plaintext.add(line.replace("P = ", ""));
            }
            if (line.startsWith("C =")) {
                // C = 031f6bd7e61e643df68594816f64caa3f56fabea2548f5fb
                ciphertext.add(line.replace("C = ", ""));
             }
            if (line.startsWith("FAIL")) {
                // FAIL
                // FAIL only occurs in decryption files
                // notice: not in every dataset available, if occurs not plaintext is shown
                flagFail.remove(countersize - 1);
                flagFail.add("true");
                plaintext.add("FAIL");
            }
        }
    }
}


