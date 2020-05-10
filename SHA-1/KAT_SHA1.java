package SHA_1;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class KAT_SHA1 {
    static List<String> header = new ArrayList<String>();
    static List<String> len = new ArrayList<String>();
    static List<String> msg = new ArrayList<String>();
    static List<String> md = new ArrayList<String>();
    static String lenFixed = "";
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


