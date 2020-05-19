/*
 * Herkunft/Origin: http://java-crypto.bplaced.net/
 * Programmierer/Programmer: Michael Fehr
 * Copyright/Copyright: frei verwendbares Programm (Public Domain)
 * Copyright: This is free and unencumbered software released into the public domain.
 * Lizenttext/Licence: <http://unlicense.org>
 * getestet mit/tested with: Java Runtime Environment 11.0.6 x64
 * verwendete IDE/used IDE: intelliJ IDEA 2019.3.4
 * Datum/Date (dd.mm.jjjj): 11.05.2020
 * Funktion: listet alle verfuegbaren Message Digests (Hashverfahren) auf
 * Function: list all available Message Digest (Hash-) methods
 * Beschreibung in / Description in
 * http://java-crypto.bplaced.net/secure-hash-algorithms/
 *
 * Sicherheitshinweis/Security notice
 * Die Programmroutinen dienen nur der Darstellung und haben keinen Anspruch auf eine korrekte Funktion,
 * insbesondere mit Blick auf die Sicherheit !
 * Pruefen Sie die Sicherheit bevor das Programm in der echten Welt eingesetzt wird.
 * The program routines just show the function but please be aware of the security part -
 * check yourself before using in the real world !
 *
 */

import java.security.Provider;
import java.security.Security;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.TreeSet;

public class List_MessageDigests {
    public static void main(String[] args) {
        System.out.println("Anzeige aller verfügbaren Message Digests (Secure Hash) in Java");
        System.out.println("\nverwendete Java version: " + Runtime.version() + " am " + getActualDate() + "\n");

        TreeSet<String> messageDigests = new TreeSet<>();
        for (Provider provider : Security.getProviders())
            for (Provider.Service service : provider.getServices())
                if (service.getType().equals("MessageDigest"))
                    messageDigests.add(service.getAlgorithm());
        for (String messageDigest : messageDigests)
            System.out.println(messageDigest);
    }

    private static String getActualDate() {
        // provides the actual date and time in this format dd-MM-yyyy_HH-mm-ss e.g. 16-03-2020_10-27-15
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd.MM.yyyy HH:mm:ss");
        LocalDateTime today = LocalDateTime.now();
        return formatter.format(today);
    }
}
