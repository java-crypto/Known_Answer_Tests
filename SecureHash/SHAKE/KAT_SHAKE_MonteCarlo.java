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
 * Funktion: fuehrt den Known Answer Test (KAT) für die SHAKE Familie im Monte Carlos Modus durch
 * Function: performs the Known Answer Test (KAT) for SHAKE family in Monte Carlo Mode
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

public class KAT_SHAKE_MonteCarlo {
    static List<String> header = new ArrayList<String>();
    static List<String> count = new ArrayList<String>();
    static List<String> output = new ArrayList<String>();
    static List<String> outputLen = new ArrayList<String>();
    static int minimumoutputLength = 0;
    static int maximumoutputLength = 0;
    static String msg = "";
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        count.clear();
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
            if (line.startsWith("[Minimum Output Length")) {
                // [Minimum Output Length (bits) = 128]
                String blockLine = line.replace("[", "");
                blockLine = blockLine.replace("]", "");
                minimumoutputLength = Integer.parseInt(blockLine.replace("Minimum Output Length (bits) = ", ""));
            }

            if (line.startsWith("[Maximum Output Length")) {
                // [Maximum Output Length (bits) = 1120]
                String blockLine = line.replace("[", "");
                blockLine = blockLine.replace("]", "");
                maximumoutputLength = Integer.parseInt(blockLine.replace("Maximum Output Length (bits) = ", ""));
            }

            if (line.startsWith("Msg = ")) {
                // Msg = c8b310cb97efa3855434998fa81c7674
                msg = line.replace("Msg = ", "");
            }

            if (line.startsWith("COUNT")) {
                // COUNT = 0
                count.add(line.replace("COUNT = ", ""));
            }
            if (line.startsWith("Outputlen")) {
                // Outputlen = 264
                outputLen.add(line.replace("Outputlen = ", ""));
            }
            if (line.startsWith("Output =")) {
                // Output = fe8c476993b47b10c98303a04c6212dfb341426d748d3926140aee0a151fc80fa1
                output.add(line.replace("Output = ", ""));
            }
        }
    }
}


