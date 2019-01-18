import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.io.OutputStream;
import java.util.Base64;
import java.security.*;

public class SessionEncrypter {

    private SessionKey sessionKey;
    private IvParameterSpec iv;
    private Cipher cipher;

    public SessionEncrypter(Integer keyLength)throws Exception{

        sessionKey = new SessionKey(keyLength);

        SecureRandom secureRandom = new SecureRandom();
        byte[] ivDummy = new byte[16];
        secureRandom.nextBytes(ivDummy);
        iv = new IvParameterSpec(ivDummy);
    }
    public SessionEncrypter(byte[] key, byte[] iv){
        this.sessionKey = new SessionKey(new String(key));
        this.iv = new IvParameterSpec(iv);
    }
    public String encodeKey(){
        return this.sessionKey.encodeKey();
    }
    public SecretKey getKey(){
        return this.sessionKey.getSecretKey();
    }
    public String encodeIV(){
        return Base64.getEncoder().encodeToString(iv.getIV());
    }
    public byte[] byteGetIV(){
        return this.iv.getIV();
    }
    public CipherOutputStream openCipherOutputStream(OutputStream output)throws Exception{
        cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, sessionKey.getSecretKey(), iv);
        return new CipherOutputStream(output, cipher);
    }
}
