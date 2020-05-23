package Block_Cipher.AES.CCM;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class KAT_CCM_VNT {
    static List<String> header = new ArrayList<String>();
    static List<String> key = new ArrayList<String>();
    static List<String> nonce = new ArrayList<String>();
    static List<String> adata = new ArrayList<String>();
    static List<String> payload = new ArrayList<String>();
    static List<String> ct = new ArrayList<String>();
    static List<String> tLen = new ArrayList<String>();
    static List<String> counter = new ArrayList<String>();
    static String tLenSaved = ""; // for multiple data in block
    static String keySaved = ""; // for multiple data in block
    private static String filename;
    private static int readLines = 0;
    private static boolean headerPhase = false;

    static void init(String fn) {
        filename = fn;
        // clear variables
        readLines = 0;
        header.clear();
        key.clear();
        nonce.clear();
        adata.clear();
        payload.clear();
        ct.clear();
        tLen.clear();
        counter.clear();
        headerPhase = true;
    }

    static String getFilename() {
        return filename;
    }

    static int getReadlines() {
        return readLines;
    }

    static boolean parse() {
        //String filename = "VNT128.rsp";
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
            if (line.startsWith("[")) {
            }
            // Tlen = 16
            if (line.startsWith("Tlen")) {
                // Tlen = 16
                tLenSaved = line.replace("Tlen = ", "");
            }
            if (line.startsWith("Key")) {
                // Key = 43b1a6bc8d0d22d6d1ca95c18593cca5
                keySaved = line.replace("Key = ", "");
            }
            if (line.startsWith("Nonce")) {
                // Nonce = 9882578e750b9682c6ca7f8f86
                nonce.add(line.replace("Nonce = ", ""));
            }
            if (line.startsWith("Count")) {
                // Count = 0
                counter.add(line.replace("Count = ", ""));
                // or data for block
                tLen.add(tLenSaved);
                key.add(keySaved);
            }
            if (line.startsWith("Adata")) {
                // Adata =   2084f3861c9ad0ccee7c63a7e05aece5db8b34bd8724cc06b4ca99a7f9c4914f
                adata.add(line.replace("Adata = ", ""));
            }
            if (line.startsWith("Payload")) {
                // Payload = a2b381c7d1545c408fe29817a21dc435a154c87256346b05
                payload.add(line.replace("Payload = ", ""));
            }
            if (line.startsWith("CT")) {
                // CT = 292ea1643d2c1ddc36b9c0b3c38cb9eb4765f8ef70e84431676e2df1
                ct.add(line.replace("CT = ", ""));
            }
        }
    }
}


