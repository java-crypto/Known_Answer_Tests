package SHA_1;

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


