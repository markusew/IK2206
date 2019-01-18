import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.util.Base64;

public class SessionDecrypter {

    private IvParameterSpec iv;
    private Cipher cipher;
    private SessionKey sessionKey;

    public SessionDecrypter(String key, String iv){

        this.iv = new IvParameterSpec(Base64.getDecoder().decode(iv));
        this.sessionKey = new SessionKey(key);

    }
    public SessionDecrypter(byte[] key, byte[] iv){
        this.sessionKey = new SessionKey(new String(key));
        this.iv = new IvParameterSpec(iv);
    }
    public CipherInputStream openCipherInputStream(InputStream input)throws Exception {
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, sessionKey.getSecretKey(), iv);
        return new CipherInputStream(input, cipher);
    }

}
