import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;


public class HandshakeCrypto {

    public static byte[] encrypt(byte[] plaintext, Key key)throws Exception{
        Cipher encrypt = Cipher.getInstance("RSA");
        encrypt.init(Cipher.ENCRYPT_MODE, key);

        return encrypt.doFinal(plaintext);
    }

    public static byte[] decrypt(byte[] ciphertext, Key key)throws Exception{
        Cipher decrypt = Cipher.getInstance("RSA");
        decrypt.init(Cipher.DECRYPT_MODE, key);

        return decrypt.doFinal(ciphertext);

    }

    public static PublicKey getPublicKeyFromCertFile(String certfile)throws Exception{
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        InputStream caIn = new FileInputStream(certfile);
        X509Certificate ca = (X509Certificate)cf.generateCertificate(caIn);
        caIn.close();
        return ca.getPublicKey();

    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile)throws Exception{
        InputStream inputStream = new FileInputStream(keyfile);
        byte[] bytePrivateKey = inputStream.readAllBytes();

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bytePrivateKey);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");

        return keyFactory.generatePrivate(keySpec);
    }
}
