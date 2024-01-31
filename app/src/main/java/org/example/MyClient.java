package org.example;

import org.example.lib.CertificateChainFactory;
import org.example.lib.ConnectionBuilder;

import javax.net.ssl.HttpsURLConnection;
import java.security.KeyStore;

public class MyClient {
    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");
        String cert = System.getProperty("cert", "client.jks");
        boolean trustAll = Boolean.parseBoolean(System.getProperty("trustAll", "true"));
        String url = System.getProperty("url", "https://localhost:9090/");

        KeyStore tls = CertificateChainFactory.getKeyStore("JKS");
        CertificateChainFactory.load(tls, cert, password);

        HttpsURLConnection connection = new ConnectionBuilder()
                .url(url)
                .clientCert(tls, password)
                .trustAll(trustAll)
                .build();

        connection.getInputStream().transferTo(System.out);
    }
}
