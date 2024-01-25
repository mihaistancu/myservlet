package org.example;

import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;

public class Main {
    public static void main(String[] args) throws Exception {
        var servlet = new MyServlet();

        KeyPair tlsKeyPair = CertificateFactory.generateKeyPair();
        X509Certificate tlsCertificate = CertificateFactory.generateCertificate(tlsKeyPair);
        String password = "password";
        KeyStore tls = CertificateFactory.generateKeyStore(tlsKeyPair.getPrivate(), tlsCertificate, password);

        var server = new JettyServerBuilder()
                .host("localhost", 8080)
                .secure(tls, password, true)
                .use("/*", servlet)
                .build();

        server.start();
    }
}