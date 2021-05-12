package io.github.mikolasan.httpsclient;

import javax.naming.ldap.LdapName;
import javax.net.ssl.*;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class CaCertHttpsClient {

    private static final SSLSocketFactory sslSocketFactory = initSSLSocketFactory();
    private static final HostnameVerifier hostnameVerifier = new GrumpyHostnameVerifier();

    private final String BASE_URL = "https://localhost/";
    private final String LOGIN = "login";
    private final int SEND_TIMEOUT = 2000; // milliseconds
    private final int RESPONSE_TIMEOUT = 3000; // milliseconds

    public void login() {
        HttpURLConnection http = null;
        try {
            http = createHttpRequest(LOGIN, SEND_TIMEOUT, RESPONSE_TIMEOUT);
            http.connect();
        } catch (SocketTimeoutException e) {
            System.out.println("Timeout.");
        } catch (Exception e){
            e.printStackTrace();
        } finally {
            System.out.println("Connect successful");
            if (http != null) {
                http.disconnect();
            }
        }
    }

    private HttpURLConnection createHttpRequest(String procedure, int connectTimeout, int readTimeout) throws IOException {
        URL url = new URL(BASE_URL + procedure);
        HttpsURLConnection https = (HttpsURLConnection)url.openConnection();
        https.setSSLSocketFactory(sslSocketFactory);
        https.setHostnameVerifier(hostnameVerifier);
        https.setRequestMethod("POST");
        https.setRequestProperty("Content-Type", "application/json");
        https.setRequestProperty("Accept", "application/json");
        https.setConnectTimeout(connectTimeout); // timeout before the connection can be established
        https.setReadTimeout(readTimeout); // timeout before there is data available for read
        https.setDoOutput(true); // Setting the doOutput flag to true indicates that the application intends to write data to the URL connection
        return https;
    }

    /*
        During handshaking, if the URL's hostname and the server's identification hostname mismatch, the verification
        mechanism can call back to implementers of this interface to determine if this connection should be allowed.

        These callbacks are used when the default rules for URL hostname verification fail.
     */
    private static class GrumpyHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            try {
                Certificate[] certificates = session.getPeerCertificates();
                // TODO: what if there are more than one certificate ?!
                if (certificates.length > 0) {
                    if (certificates[0] instanceof X509Certificate) {
                        X509Certificate certificate = (X509Certificate) certificates[0];
                        String dn = certificate.getSubjectX500Principal().getName();
                        String commonName = new LdapName(dn)
                                .getRdns()
                                .stream()
                                .filter(rdn ->
                                        rdn.getType().equalsIgnoreCase("CN"))
                                .findFirst()
                                .get()
                                .getValue()
                                .toString();
                        System.out.println("Certificate is signed for '" + commonName + "', but real hostname is '" + hostname + "'. Be aware of possible MITM attack");
                    }
                }
                return true;
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
            return false;
        }
    }

    private static SSLSocketFactory initSSLSocketFactory() {
        try {
            InputStream stream = CaCertHttpsClient.class.getClassLoader().getResourceAsStream("ca.crt");
            Certificate certificate = CertificateFactory
                    .getInstance("X.509")
                    .generateCertificate(stream);

            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("mikolasan", certificate);

            TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            trustManagerFactory.init(keyStore);

            SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
            sslContext.init(null, trustManagerFactory.getTrustManagers(), null);
            return sslContext.getSocketFactory();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}