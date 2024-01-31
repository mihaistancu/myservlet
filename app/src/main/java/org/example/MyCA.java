package org.example;

import com.eclipsesource.json.Json;
import com.eclipsesource.json.JsonArray;
import com.eclipsesource.json.JsonObject;
import org.example.lib.CertificateChainFactory;

import java.io.FileOutputStream;
import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x509.Extension;

public class MyCA {
    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");

        String defaultJson =
                """
                [{"name": "CN=root"},{"name": "CN=intermediate"},{"name": "CN=leaf", "ocsp": "http://localhost:9091", "crl":"http://localhost:9092"}]
                """;

        JsonArray certs = Files.exists(Path.of("certs.json"))
                ? Json.parse(new FileReader("certs.json")).asArray()
                : Json.parse(defaultJson).asArray();

        String lastName = null;
        KeyPair lastKeyPair = null;

        for (int i=0; i<certs.size(); i++) {
            KeyPair keyPair = CertificateChainFactory.generateKeyPair();

            JsonObject cert = certs.get(i).asObject();
            String name = cert.getString("name", "localhost");
            boolean isCA = i != certs.size() - 1;

            List<Extension> extensions = new ArrayList<>();

            if (isCA) {
                extensions.add(CertificateChainFactory.createExtendedKeyUsage());
                extensions.add(CertificateChainFactory.createSubjectAlternativeNames());
            }

            String ocsp = cert.getString("ocsp", null);
            if (ocsp != null) {
                extensions.add(CertificateChainFactory.createOcspEndpoint(ocsp));
            }

            String crl = cert.getString("crl", null);
            if (crl != null) {
                extensions.add(CertificateChainFactory.createCrlEndpoint(crl));
            }

            X509Certificate x509 = CertificateChainFactory.generateCertificate(name, keyPair, lastName, lastKeyPair, isCA, 1, extensions);

            KeyStore jks = CertificateChainFactory.generateKeyStore(keyPair.getPrivate(), x509, password, "JKS");
            jks.store(new FileOutputStream(i + ".jks"), password.toCharArray());

            KeyStore pfx = CertificateChainFactory.generateKeyStore(keyPair.getPrivate(), x509, password, "PKCS12");
            pfx.store(new FileOutputStream(i + ".pfx"), password.toCharArray());

            lastName = name;
            lastKeyPair = keyPair;
        }
    }
}
