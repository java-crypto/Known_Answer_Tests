package SHAKE;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 18.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) für die SHAKE Familie durch
 * Function: performs the Known Answer Test (KAT) for SHAKE family
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/shake-kat/
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

public class KAT_SHAKE_VariableOut {
    static List<String> header = new ArrayList<String>();
    static List<String> count = new ArrayList<String>();
    static List<String> msg = new ArrayList<String>();
    static List<String> output = new ArrayList<String>();
    static List<String> outputLen = new ArrayList<String>();
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        count.clear();
        msg.clear();
        output.clear();
        outputLen.clear();
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
            if (line.startsWith("COUNT")) {
                // COUNT = 0
                count.add(line.replace("COUNT = ", ""));
            }
            if (line.startsWith("Outputlen")) {
                // Outputlen = 128
                outputLen.add(line.replace("Outputlen = ", ""));
            }
            if (line.startsWith("Msg")) {
                // Msg = 84e950051876050dc851fbd99e6247b8
                msg.add(line.replace("Msg = ", ""));
            }
            if (line.startsWith("Output =")) {
                // Output = 7f9c2ba4e88f827d616045507605853e
                output.add(line.replace("Output = ", ""));
            }
        }
    }
}


