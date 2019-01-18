import java.security.cert.*;

public class VerifyCertificate {

    private X509Certificate ca;
    private X509Certificate user;

    public VerifyCertificate(X509Certificate caCert, X509Certificate clientCert) {
        this.ca = caCert;
        this.user = clientCert;
    }

    void testValidity() {
        System.out.println("CA:   " + ca.getSubjectDN());
        System.out.println("USER: " + user.getSubjectDN());
        try {
            this.ca.checkValidity();
            this.user.checkValidity();

            this.ca.verify(ca.getPublicKey());
            this.user.verify(ca.getPublicKey());
        } catch (Exception e) {
            System.out.println("Fail");
            System.out.println(e.getMessage());
            System.exit(0);
        }
        System.out.println("Pass");
    }
}
