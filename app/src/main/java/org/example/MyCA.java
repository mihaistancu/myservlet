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
import org.bouncycastle.asn1.x509.Extension;

public class MyCA {
    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");

        String defaultJson =
                """
                [{"name": "CN=root"},{"name": "CN=intermediate"},{"name": "CN=leaf"}]
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
            Extension[] extensions = isCA ? new Extension[0] : new Extension[]{
                    CertificateChainFactory.createExtendedKeyUsage(),
                    CertificateChainFactory.createSubjectAlternativeNames()
            };

            X509Certificate x509 = CertificateChainFactory.generateCertificate(name, keyPair, lastName, lastKeyPair, isCA, 1, extensions);

            KeyStore keyStore = CertificateChainFactory.generateKeyStore(keyPair.getPrivate(), x509, password);
            keyStore.store(new FileOutputStream(i + ".jks"), password.toCharArray());

            lastName = name;
            lastKeyPair = keyPair;
        }
    }
}
