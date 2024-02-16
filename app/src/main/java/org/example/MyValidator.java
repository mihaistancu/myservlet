package org.example;

import org.example.lib.CertificateValidation;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertPath;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

public class MyValidator {
    public static void main(String[] args) throws Exception {
        String certificatePath = System.getProperty("certificate", "cert.cer");
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new FileInputStream(certificatePath));
        CertPath certPath = factory.generateCertPath(List.of(certificate));

        String rootPath = System.getProperty("trusted", "trusted.jks");
        String password = System.getProperty("password", "password");
        KeyStore trustStore = KeyStore.getInstance("JKS");
        trustStore.load(new FileInputStream(rootPath), password.toCharArray());

        boolean checkRevocation = Boolean.parseBoolean(System.getProperty("revocation", "true"));

        CertificateValidation.validate(certPath, trustStore, checkRevocation);
    }
}
