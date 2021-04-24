import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKey {

    public static PrivateKey privateKey;
    public static PublicKey publicKey;
    /**
     * Membentuk kunci pair public dan private
     */
    public static void generateKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        KeyPair pair = generator.generateKeyPair();
        privateKey = pair.getPrivate();
        publicKey = pair.getPublic();
    }
    /**
     * Membentuk kunci public dari file tersimpan
     */
    public static void getPublicKeyFromFile() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        File publicKeyFile = new File("public.key");
        byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        publicKey = keyFactory.generatePublic(publicKeySpec);
    }
    /**
     * Membentuk kunci private dari file tersimpan
     */
    public static void getPrivateKeyFromFile() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException {
        File privateKeyFile = new File("private.key");
        byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec privateKeySpec = new X509EncodedKeySpec(privateKeyBytes);
        keyFactory.generatePrivate(privateKeySpec);
        privateKey = keyFactory.generatePrivate(privateKeySpec);
    }
    /**
     * Menulis public dan private key
     */
    public static void writeToFile() throws IOException {
        File f;
        FileOutputStream fos;
        f = new File("public.key");
        fos = new FileOutputStream(f);
        fos.write(publicKey.getEncoded());
        fos.close();
        f = new File("private.key");
        fos = new FileOutputStream(f);
        fos.write(privateKey.getEncoded());
        fos.close();
    }
    /**
     * Mendapatkan kunci private sebagai string
     */
    public static String getPrivateKeyAsString() {
        return Base64.getEncoder().encodeToString(privateKey.getEncoded());
    }
    /**
     * Mendapatkan kunci public sebagai string
     */
    public static String getPublicKeyAsString() {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
    /**
     * Mendapatkan kunci private
     */
    public static PrivateKey getPrivateKey() {
        return privateKey;
    }
    /**
     * Mendapatkan kunci public
     */
    public static PublicKey getPublicKey() {
        return publicKey;
    }
}