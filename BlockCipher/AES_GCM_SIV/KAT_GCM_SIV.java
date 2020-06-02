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

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class KAT_GCM_SIV {
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;

    static List<String> header = new ArrayList<String>();
    static List<String> key = new ArrayList<String>();
    static List<String> nonce = new ArrayList<String>();
    static List<String> adata = new ArrayList<String>();
    static List<String> plaintext = new ArrayList<String>();
    static List<String> counter = new ArrayList<String>();
    static List<String> result = new ArrayList<String>();

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        key.clear();
        nonce.clear();
        adata.clear();
        plaintext.clear();
        counter.clear();
        result.clear();
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
                // System.out.println("zeile " + zeilennummer + " inhalt: " + line + "§"); // '§' is no letter in kat-file
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
            if (line.startsWith("   Key")) {
                //   Key =                       01000000000000000000000000000000
                key.add(cutLeft(line, 31));
            }
            if (line.startsWith("   Nonce")) {
                //    Nonce =                     030000000000000000000000
                nonce.add(cutLeft(line, 31));
            }
            if (line.startsWith("   AAD")) {
                //    AAD (1 bytes) =             01
                if (line.startsWith("   AAD (0 bytes) =")) { // = 0
                    adata.add("");
                } else {
                    adata.add(cutLeft(line, 31));
                }
            }
            if (line.startsWith("   Plaintext")) {
                //    Plaintext (8 bytes) =       0100000000000000
                if (line.startsWith("   Plaintext (0 bytes) =")) { // = 0
                    plaintext.add("");
                } else {
                    plaintext.add(cutLeft(line, 31));
                }
            }
            if (line.startsWith("   Result")) {
                //    Result (24 bytes) =         1e6daba35669f4273b0a1a2560969cdf
                //                               790d99759abd1508
                result.add(cutLeft(line, 31));
            }
        }
    }
    private static String cutLeft(String input, int leftChars) {
        return input.substring(leftChars);
    }
}
