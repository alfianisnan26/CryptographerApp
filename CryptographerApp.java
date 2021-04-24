
/**
 * Aplikasi ini merupakan tugas untuk memenuhi Tugas Tambahan Modul 7 : Secure Information
 * Praktikum Keamanan Jaringan, Teknik Komputer, Departemen Teknik Elektro
 * Fakultas Teknik, Universitas Indoensia
 * 
 * Class CryptographerApp merupakan class utama dari program ini
 * Jalankan CryptographerApp tanpa parameter akan melakukan testing program sesuai dengan soal
 * pada Tugas Tambahan
 * 
 * (MD5) SecureCommunication
 * >> CryptographerApp SecureCommunication
 * (MD5) Computer_Security
 * >> CryptographerApp Computer_Security
 * (SHA1) "When there’s a will, there's a way."
 * >> CryptographerApp --algorithm SHA1 "When there’s a will, there's a way."
 * (RSA) "Man is a slow, sloppy, and brilliant thinker; computers are fast, accurate, and stupid."
 * >> CryptographerApp --keypairs
 * >> CryptographerApp --encrypt --showkey --tofile encrypted.data "Man is a slow, sloppy, and brilliant thinker; computers are fast, accurate, and stupid."
 * >> CryptographerApp --decrypt encrypted.data --private [private]
 * 
 * Dependency
 * RSAKey.java
 * RSAUtil.java
 * 
 * @version 1.026 BETA
 * @author Alfian Badrul Isnan - 1806148643
 */

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;

public class CryptographerApp {
    final static String version = "1.026 BETA";
    /**
     * Menampilkan Sequence testing dari program
     * Secara default, akan mencoba melakukan proses hashing dan pembentukan RSA sesuai dengan
     * perintah pada studi kasus tugas tambahan.
     */
    public static void defaultOWH() {
        System.out.println("\nDefault Program");
        final String[] md5test = { "SecureCommunication", "Computer_Security", "-a", "MD5" };
        final String[] sha1test = { "-a", "SHA1", "When there’s a will, there's a way." };
        final String[] rsateste = { "-e", "--tofile", "encrypted.data", "--showkey",
                "Man is a slow, sloppy, and brilliant thinker; computers are fast, accurate, and stupid." };
        messageOWH(md5test);
        messageOWH(sha1test);
        final String[] generateKey = { "--keypairs" };
        CryptographerApp.main(generateKey);
        rsaEncryptDecrypt(rsateste);
        final String[] rsatestd = { "-d", "encrypted.data",};
        rsaEncryptDecrypt(rsatestd);
    }
    /**
     * Menampilkan bantuan dari command yang tersedia
     */
    public static void helpOWH() {
        System.out.println("\nCommand : ");
        System.out.println("(no command) \t\t\t : Default program for testing");
        System.out.println("[any input] ...\t\t\t : Hash for multiple message");
        System.out.println("--file [file] | -f [file]\t : Hash file from defined directory");
        System.out.println("--version | -v \t\t\t : version and about this simple software");
        System.out.println("--help | -h \t\t\t : This help page");
        System.out.println("--algorithm | -a \t\t : Hashing with specific algorithm (ex: MD5 | SHA1 | SHA256)");
        System.out.println("--encrypt | -e\t\t\t : Encrypt message/file with RSA");
        System.out.println("--decrypt | -d\t\t\t : Decrypt message/file with RSA");
        System.out.println("--tofile [file] | -tf [file]\t\t\t : Export encrypted.data to root directory");
        System.out.println("--keypairs | -kp\t\t\t : Generate New Keypair (Private & Public) Key");
        System.out.println("--showkey | -sh\t\t\t : Show key next to data");
        System.out.println("--private [key] | -P [key]\t\t\t : Manually input private key");
        System.out.println("--public [key] | -p [key]\t\t\t : Manually input public key");
        System.out
                .println("\nExample (Program will run on JVM)\n>> CryptographerApp \"Hello World\" Password123 -a MD5");
        System.out.println(">> CryptographerApp -algorithm SHA256 --file \"C:\\Documents\\test.txt\"");
        System.out.println(">> CryptographerApp HelloWorld");
        System.out.println(">> CryptographerApp --encrypt \"This is my secret message\"");
        System.out.println(">> CryptographerApp HelloWorld123 --decrypt --tofile .");
        System.out.println(">> CryptographerApp -e C:\\Documents\\secretMessage.txt");
    }
    /**
     * Menampilkan versi dan tentang aplikasi
     */
    public static void versionOWH() {
        System.out.println("by Alfian Badrul Isnan - 1806148643");
        System.out.println("\nVersion : " + version);
        System.out.println("alfian.badrul@ui.ac.id | fianshared@gmail.com | git:alfianisnan10");
        System.out.println("\nAplikasi ini merupakan tugas untuk memenuhi Tugas Tambahan Modul 7 : Secure Information");
        System.out.println("Praktikum Keamanan Jaringan, Teknik Komputer, Departemen Teknik Elektro");
        System.out.println("Fakultas Teknik, Universitas Indoensia");
        System.out.println("\nSukabumi, 25 April 2020");
    }
    /**
     * Membentuk MessageDigest sesuai input --algoritm | -a
     * Secara default, data akan diterjemahkan kedalam MD5
     * @param args argument dari input program
     */
    public static void messageOWH(final String[] args) {
        final ArrayList<String> alist = new ArrayList<>();
        System.out.println();
        Collections.addAll(alist, args);
        /**
         * Proses pencarian data jika input merupakan sebuah file
         */
        if (alist.stream().anyMatch(a -> a.equals("-f") || a.equals("--file"))) {
            fileOWH(alist);
            return;
        }
        /**
         * Mengambil dan menentukan algoritma sesuai input atau penggunaan sesuai default
         */
        final MessageDigest md = getAlgorithm(alist);
        if (md == null)
            return;
        System.out.println("(" + md.getAlgorithm() + ")");
        /**
         * Membentuk digest sesuai input data yang diberikan bergantung pada jenis
         * Algortima Digest yang digunakan
         */
        alist.forEach(a -> {
            byte[] messageDigest = md.digest(a.getBytes());
            BigInteger no = new BigInteger(1, messageDigest);
            String hashtext = no.toString(16);
            while (hashtext.length() < 32)
                hashtext = "0" + hashtext;
            System.out.println(hashtext + " : " + a);
        });
    }
    /**
     * Membentuk Digest jika input merupakan sebuah file
     * @param alist berupa argumen input dari pengguna
     */
    public static void fileOWH(ArrayList<String> alist) {
        alist.removeIf(f -> f.equals("-f") || f.equals("--file"));
        /**
         * Mengambil dan menentukan algoritma dari digest sesuai input atau sesuai parameter default
         */
        final MessageDigest md = getAlgorithm(alist);
        if (md == null)
            return;
        System.out.println("(" + md.getAlgorithm() + ")");
        /**
         * Membentuk digest sebagai checksum dari file input
         */
        alist.forEach(a -> {
            System.out.println(checksum(md, new File(a)) + " : " + a);
        });
    }
    /**
     * Menentukan algortima, default = MD5, lainnya sesuai input pengguna
     * dengan menggunakan input command --algorithm | -a
     * @param alist
     * @return
     */
    private static MessageDigest getAlgorithm(ArrayList<String> alist) {
        String algo = "MD5";
        int algoPos = alist.indexOf("-a");
        if (algoPos < 0)
            algoPos = alist.indexOf("--algorithm");
        if (algoPos >= 0 && alist.size() > 2) {
            algo = alist.get(algoPos + 1);
            alist.remove(algoPos);
            alist.remove(algoPos);
        }

        try {
            return MessageDigest.getInstance(algo);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Algorithm does not recognized (" + algo + ")");
            return null;
        }
    }
    /**
     * Membentuk chekcsum jika input adalah sebuah file
     * @param digest
     * @param file
     * @return
     */
    private static String checksum(MessageDigest digest, File file) {
        FileInputStream fis;
        try {
            fis = new FileInputStream(file);
        } catch (FileNotFoundException e) {
            return "No such file";
        }
        byte[] byteArray = new byte[1024];
        int bytesCount = 0;
        try {
            while ((bytesCount = fis.read(byteArray)) != -1) {
                digest.update(byteArray, 0, bytesCount);
            }
        } catch (IOException e) {
            return "Error Reading File";
        }
        ;
        try {
            fis.close();
        } catch (IOException e) {
            return "Error Closing File";
        }
        byte[] bytes = digest.digest();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
    /**
     * Enkripsi dan dekripsi dengan teknik RSA
     * dependensi dengan :
     * RSAKey.java (pembentukan key public dan private)
     * RSAUtil.java (pembentukan enkripsi data)
     */
    public static void rsaEncryptDecrypt(String[] args) {
        final ArrayList<String> alist = new ArrayList<>();
        System.out.println();
        Collections.addAll(alist, args);
        alist.removeIf(a -> a.equals("-e") || a.equals("--encrypt"));
        boolean isDecrypt = alist.removeIf(a -> a.equals("-d") || a.equals("--decrypt"));
        boolean isShown = alist.removeIf(a -> a.equals("-sh") || a.equals("--showkey"));
        int check = alist.indexOf("--private");
        if (check < 0)
            check = alist.indexOf("-P");
        if(check >= 0){
            alist.remove(check);
            RSAKey.privateKey = RSAUtil.getPrivateKey(alist.get(check));
            alist.remove(check);
        }
        check = alist.indexOf("--public");
        if (check < 0)
            check = alist.indexOf("-p");
        if(check >= 0){
            alist.remove(check);
            RSAKey.publicKey = RSAUtil.getPublicKey(alist.get(check));
            alist.remove(check);
        }
        final String filename;
        int tofileindex = alist.indexOf("--tofile");
        if (tofileindex < 0)
            tofileindex = alist.indexOf("-tf");
        if (tofileindex >= 0) {
            try {
                alist.remove(tofileindex);
                filename = alist.get(tofileindex);
                alist.remove(tofileindex);
            } catch (Exception e) {
                System.err.println("Error! Check your command -h | --help for guides");
                return;
            }
        } else {
            filename = null;
        }
        /**
         * Proses generasi data terenkripsi
         */
        alist.forEach(msg -> {
            File isFile = new File(msg);
            byte[] bmsg = msg.getBytes();
            byte[] data;
            if (isFile.canRead()) {
                try {
                    bmsg = Files.readAllBytes(isFile.toPath());
                } catch (IOException e) {
                    System.err.println("Cannot Read File of : " + isFile.getName());
                    return;
                }
            }
            System.out.println("Original Data : " + msg);
            if (isDecrypt) {
                /**
                 * Proses Dekripsi Data
                 * Mengambil Private Key
                 * Membuka Kucinya dengan private key
                 * Output data Asli
                 */
                if (RSAKey.getPrivateKey() == null) {
                    try {
                        RSAKey.getPrivateKeyFromFile();
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e1) {
                        System.err
                                .println("Cannot Find private.key files, please create new pair of keys (--keypairs)");
                        return;
                    }
                }
                try {
                    data = RSAUtil.decrypt(bmsg, RSAKey.getPrivateKey());
                } catch (Exception e) {
                    System.err.println("Cannot Decrypt Message");
                    return;
                }
            } else {
                /**
                 * Proses Enkripsi
                 * Membentuk Public Key
                 * Menguncinya dengan Public Key
                 * Membentuk Private key dari penguncian data sebagai data terenkripsi
                 */
                if (RSAKey.getPublicKey() == null) {
                    try {
                        RSAKey.getPublicKeyFromFile();
                    } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e1) {
                        System.err.println("Cannot Find public.key files, please create new pair of keys (--keypairs)");
                        return;
                    }
                }
                try {
                    data = RSAUtil.encrypt(bmsg, RSAKey.getPublicKeyAsString());
                } catch (Exception e) {
                    System.err.println("Cannot Encrypt Message");
                    return;
                }
            }
            if (filename != null) {
                File file = new File(filename);
                try {
                    FileOutputStream fos = new FileOutputStream(file);
                    fos.write(data);
                    fos.flush();
                    fos.close();
                } catch (IOException e) {
                    System.err.println("Cannot Generate Encrypted File");
                }
                System.out.println("Exported to : " + file.getAbsolutePath());
            } else {
                System.out.println((isDecrypt) ? "Decrypted : " + new String(data)
                        : "Encrypted : " + Base64.getEncoder().encodeToString(data));
            }
            if (isShown) {
                System.out.println("Public Key  : \n" + RSAKey.getPublicKeyAsString());
                System.out.println("Private Key : \n" + RSAKey.getPrivateKeyAsString());
            }
        });

    }
    /**
     * Main methode
     * @param args argumen dari input pengguna
     */
    public static void main(String[] args) {
        System.out.println("\nCryptographerApp Simple Software");
        if (args.length == 0)
            defaultOWH();
        else if (args[0].equals("--encrypt") || args[0].equals("-e") || args[0].equals("--decrypt")
                || args[0].equals("-d"))
            rsaEncryptDecrypt(args);
        else if (args[0].equals("--help") || args[0].equals("-h"))
            helpOWH();
        else if (args[0].equals("--version") || args[0].equals("-v"))
            versionOWH();
        else if (args[0].equals("--keypairs") || args[0].equals("-kp")) {
            try {
                RSAKey.generateKeyPair();
                RSAKey.writeToFile();
                System.out.println("Successfull generating public.key and private.key");
            } catch (IOException | NoSuchAlgorithmException e) {
                System.err.println("Cannot Generate New Keypair");
                e.printStackTrace();
            }
        } else
            messageOWH(args);
        System.out.println();
    }
}