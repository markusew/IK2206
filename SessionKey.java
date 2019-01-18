import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.security.*;

public class SessionKey {

    private SecretKey secretKey;

    public SessionKey(Integer keyLength) throws NoSuchAlgorithmException {
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(keyLength);
        secretKey = keyGen.generateKey();
    }
    public SessionKey(String encodedKey){
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        secretKey = new SecretKeySpec(decodedKey, "AES");

    }
    public SecretKey getSecretKey(){
        return secretKey;
    }
    public String encodeKey(){
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }
}
/*
Discussion:
Key quality is how secure the key is. How secure a key is depends on the length and what algorithm was used to generate
the key. It is important that the algorithm is random and making a key incredibly long is a waste because there is a
upper bound to how large keys you are able to brute force.
To test key quality you can create a bunch of keys of the same length and compare them to ensure that they are random
and do not follow a predictable pattern.
*/