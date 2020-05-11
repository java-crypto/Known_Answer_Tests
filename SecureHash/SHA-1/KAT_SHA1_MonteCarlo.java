package SHA_1;

/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 10.05.2020
 * Funktion: fuehrt den Known Answer Test (KAT) im Monte Carlo Modus für SHA-1 durch
 * Function: performs the Known Answer Test (KAT) in Monte Carlo mode for SHA-1
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/sha-1-kat/
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

public class KAT_SHA1_MonteCarlo {
    static List<String> header = new ArrayList<String>();
    static List<String> seed = new ArrayList<String>();
    static List<String> count = new ArrayList<String>();
    static List<String> md = new ArrayList<String>();
    static String seedFixed = "";
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;
    // data
    int counterInternal = 0;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        seed.clear();
        count.clear();
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
            if (line.startsWith("Seed")) {
                // Seed = dd4df644eaf3d85bace2b21accaa22b28821f5cd
                seedFixed = line.replace("Seed = ", "");
            }
            if (line.startsWith("COUNT")) {
                // COUNT = 0
                count.add(line.replace("COUNT = ", ""));
            }
            if (line.startsWith("MD")) {
                // MD = 11f5c38b4479d4ad55cb69fadf62de0b036d5163
                md.add(line.replace("MD = ", ""));
                seed.add(seedFixed);
            }
        }
    }
}


