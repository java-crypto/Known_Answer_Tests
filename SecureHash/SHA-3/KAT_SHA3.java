package SHA_3;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 17.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für die SHA-3 Familie durch
 * Function: performs the Known Answer Test (KAT) for SHA-3 family
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/sha-3-kat/
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

public class KAT_SHA3 {
    static List<String> header = new ArrayList<String>();
    static List<String> len = new ArrayList<String>();
    static List<String> msg = new ArrayList<String>();
    static List<String> md = new ArrayList<String>();
    static String lenFixed = "";
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        len.clear();
        msg.clear();
        md.clear();
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
            if (line.startsWith("Len")) {
                // Len = 0
                if (line.contentEquals("Len = 0")) {
                    lenFixed = "0";
                } else
                    lenFixed = "1";
                len.add(line.replace("Len = ", ""));
            }
            if (line.startsWith("Msg")) {
                // Msg = 00
                if (lenFixed == "0") {
                    msg.add("");
                } else {
                    msg.add(line.replace("Msg = ", ""));
                }
            }
            if (line.startsWith("MD")) {
                // MD = da39a3ee5e6b4b0d3255bfef95601890afd80709
                md.add(line.replace("MD = ", ""));
            }
        }
    }
}


