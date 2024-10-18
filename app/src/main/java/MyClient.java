import lib.CertificateChainFactory;
import lib.ConnectionBuilder;

import javax.net.ssl.HttpsURLConnection;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.security.Security;

public class MyClient {
    public static void main(String[] args) throws Exception {
        String url = System.getProperty("url", "https://localhost:9090/");
        String method = System.getProperty("method", "GET");

        String useBC = System.getProperty("useBC", "false");
        if (useBC.equals("true")) {
            Security.insertProviderAt(new org.bouncycastle.jce.provider.BouncyCastleProvider(), 1);
            Security.insertProviderAt(new org.bouncycastle.jsse.provider.BouncyCastleJsseProvider(), 2);
        }

        var builder = new ConnectionBuilder()
                .url(url)
                .method(method);
        if (url.startsWith("https")) {
            String cert = System.getProperty("cert", null);
            if (cert != null) {
                String password = System.getProperty("password", "password");
                KeyStore tls = CertificateChainFactory.getKeyStore("JKS");
                CertificateChainFactory.load(tls, cert, password);
                builder.clientCert(tls, password);
            }

            boolean trustAll = Boolean.parseBoolean(System.getProperty("trustAll", "true"));
            builder.trustAll(trustAll);
        }

        HttpURLConnection connection = builder.build();
        connection.getInputStream().transferTo(System.out);
    }
}
