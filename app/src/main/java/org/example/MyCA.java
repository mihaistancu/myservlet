package org.example;

import org.bouncycastle.asn1.x509.Extension;
import org.example.lib.CertificateChainFactory;

import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import static org.example.lib.CertificateChainFactory.getKeyPair;

public class MyCA {
    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");

        KeyPair keyPair = CertificateChainFactory.generateKeyPair();

        String name = System.getProperty("name", "root");
        String issuer = System.getProperty("issuer", name);

        KeyPair issuerKeyPair = issuer.equalsIgnoreCase(name)
                ? keyPair
                : getKeyPair(issuer + ".jks", password);

        boolean isCA = Boolean.parseBoolean(System.getProperty("ca", "true"));
        String ocsp = System.getProperty("ocsp", null);
        String crl = System.getProperty("crl", null);

        List<Extension> extensions = new ArrayList<>();

        if (!isCA) {
            extensions.add(CertificateChainFactory.createExtendedKeyUsage());
            extensions.add(CertificateChainFactory.createSubjectAlternativeNames());
        }

        if (ocsp != null) {
            extensions.add(CertificateChainFactory.createOcspEndpoint(ocsp));
        }

        if (crl != null) {
            extensions.add(CertificateChainFactory.createCrlEndpoint(crl));
        }

        X509Certificate x509 = CertificateChainFactory.generateCertificate("CN=" + name, keyPair, "CN=" + issuer, issuerKeyPair, isCA, 1, extensions);

        KeyStore jks = CertificateChainFactory.generateKeyStore(keyPair.getPrivate(), x509, password, "JKS");
        jks.store(new FileOutputStream(name + ".jks"), password.toCharArray());

        KeyStore pfx = CertificateChainFactory.generateKeyStore(keyPair.getPrivate(), x509, password, "PKCS12");
        pfx.store(new FileOutputStream(name + ".pfx"), password.toCharArray());
    }
}
