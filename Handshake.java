import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class Handshake {
    /* Static data -- replace with handshake! */

    /* Where the client forwarder forwards data from  */
    private String serverHost;
    private int serverPort;

    /* The final destination */
    private String targetHost;
    private int targetPort;

    private CertificateFactory cf = CertificateFactory.getInstance("X.509");
    private X509Certificate clientCert;
    private X509Certificate CACert;
    private X509Certificate serverCert;

    private SessionEncrypter sessionEncrypter;
    private SessionDecrypter sessionDecrypter;

    public Handshake() throws CertificateException {
    }


    public void clientHello(String usercert, Socket socket) throws CertificateException, IOException {
        HandshakeMessage clientHello = new HandshakeMessage();
        InputStream clientCertIn = new FileInputStream(usercert);
        clientCert = (X509Certificate)cf.generateCertificate(clientCertIn);

        String clientCertString = Base64.getEncoder().encodeToString(clientCert.getEncoded());
        clientHello.putParameter("MessageType", "ClientHello");
        clientHello.putParameter("Certificate", clientCertString);
        clientHello.send(socket);
    }
    public void serverHello(String usercert, String cacert, Socket clientSocket) throws CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException {
        HandshakeMessage serverHello = new HandshakeMessage();
        HandshakeMessage fromClientHello = new HandshakeMessage();
        fromClientHello.recv(clientSocket);
        if(fromClientHello.getParameter("MessageType").equals("ClientHello")){
            String clientCertString = fromClientHello.getParameter("Certificate");
            byte[] clientCertBytes = Base64.getDecoder().decode(clientCertString);
            InputStream clientCertIn = new ByteArrayInputStream(clientCertBytes);
            clientCert = (X509Certificate) cf.generateCertificate(clientCertIn);

            InputStream CACertIn = new FileInputStream(cacert);
            CACert = (X509Certificate) cf.generateCertificate(CACertIn);

            new VerifyCertificate(CACert, clientCert).testValidity();

            System.out.println("The client certificate was validated.");

            InputStream serverCertIn = new FileInputStream(usercert);
            serverCert = (X509Certificate) cf.generateCertificate(serverCertIn);

            String serverCertString = Base64.getEncoder().encodeToString(serverCert.getEncoded());
            serverHello.putParameter("MessageType", "ServerHello");
            serverHello.putParameter("Certificate", serverCertString);
            serverHello.send(clientSocket);
        }else{
            System.out.println("There was an error in the ServerHello");
            clientSocket.close();
        }
    }
    public void forwardMessage(String targetHost, String targetPort, String cacert, Socket socket) throws IOException, CertificateException, NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        HandshakeMessage forwardMessage = new HandshakeMessage();
        HandshakeMessage fromServerHello = new HandshakeMessage();
        fromServerHello.recv(socket);
        if (fromServerHello.getParameter("MessageType").equals("ServerHello")) {
            String serverCertString = fromServerHello.getParameter("Certificate");
            byte[] serverCertBytes = Base64.getDecoder().decode(serverCertString);
            InputStream serverCertIn = new ByteArrayInputStream(serverCertBytes);
            serverCert = (X509Certificate) cf.generateCertificate(serverCertIn);

            InputStream CACertIn = new FileInputStream(cacert);
            CACert = (X509Certificate) cf.generateCertificate(CACertIn);

            new VerifyCertificate(CACert, serverCert).testValidity();

            System.out.println("The server certificate was validated.");

            forwardMessage.putParameter("MessageType", "Forward");
            forwardMessage.putParameter("TargetHost", targetHost);
            forwardMessage.putParameter("TargetPort", targetPort);
            forwardMessage.send(socket);
        } else {
            System.out.println("There was an error in the ForwardMessage");
            socket.close();
        }
    }
    public void sessionMessage(String serverHost, String serverPort, Socket clientSocket) throws Exception {
        HandshakeMessage sessionMessage = new HandshakeMessage();
        HandshakeMessage fromForwardMessage = new HandshakeMessage();
        fromForwardMessage.recv(clientSocket);
        if(fromForwardMessage.getParameter("MessageType").equals("Forward")) {
            targetHost = fromForwardMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(fromForwardMessage.getParameter("TargetPort"));

            sessionEncrypter = new SessionEncrypter(128);
            sessionDecrypter = new SessionDecrypter(sessionEncrypter.encodeKey(), sessionEncrypter.encodeIV());
            PublicKey clientPublicKey = clientCert.getPublicKey();

            byte[] encryptedSessionKeyByte = HandshakeCrypto.encrypt(sessionEncrypter.encodeKey().getBytes(), clientPublicKey);
            byte[] encryptedIVByte = HandshakeCrypto.encrypt(sessionEncrypter.byteGetIV(), clientPublicKey);

            String encryptedIV = Base64.getEncoder().encodeToString(encryptedIVByte);
            String encryptedSessionKey = Base64.getEncoder().encodeToString(encryptedSessionKeyByte);

            System.out.println(Base64.getEncoder().encodeToString(sessionEncrypter.getKey().getEncoded()));
            System.out.println(Base64.getEncoder().encodeToString(sessionEncrypter.byteGetIV()));

            sessionMessage.putParameter("MessageType", "Session");
            sessionMessage.putParameter("SessionKey", encryptedSessionKey);
            sessionMessage.putParameter("SessionIV", encryptedIV);
            sessionMessage.putParameter("ServerHost", serverHost);
            sessionMessage.putParameter("ServerPort", serverPort);
            sessionMessage.send(clientSocket);

        }else{
            System.out.println("There was an error in the SessionMessage");
            clientSocket.close();
        }
    }
    public void finishHandshake(Socket socket, String clientPrivateKeyName) throws Exception {
        HandshakeMessage finishHandshake = new HandshakeMessage();
        finishHandshake.recv(socket);
        if (finishHandshake.getParameter("MessageType").equals("Session")) {

            serverHost = finishHandshake.getParameter("ServerHost");
            serverPort = Integer.parseInt(finishHandshake.getParameter("ServerPort"));

            PrivateKey clientsPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(clientPrivateKeyName);

            byte[] decryptedKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(finishHandshake.getParameter("SessionKey")), clientsPrivateKey);
            byte[] decryptedIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(finishHandshake.getParameter("SessionIV")), clientsPrivateKey);

            sessionEncrypter = new SessionEncrypter(decryptedKey, decryptedIV);
            sessionDecrypter = new SessionDecrypter(decryptedKey, decryptedIV);

            System.out.println(Base64.getEncoder().encodeToString(sessionEncrypter.getKey().getEncoded()));
            System.out.println(Base64.getEncoder().encodeToString(sessionEncrypter.byteGetIV()));

            System.out.println("Handshake complete!");
        } else {
            System.out.println("Error: MessageType != Session");
            socket.close();
        }
    }
    public String getTargetHost() {
        return targetHost;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public String getServerHost() {
        return serverHost;
    }

    public int getServerPort() {
        return serverPort;
    }
    public SessionEncrypter getSessionEncrypter() {
        return sessionEncrypter;
    }

    public SessionDecrypter getSessionDecrypter() {
        return sessionDecrypter;
    }

}
