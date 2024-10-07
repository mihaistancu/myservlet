import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Enumeration;

public class MyTrust {
    public static void main(String[] args) throws Exception {
        String keystorePath = System.getProperty("keystore.path", "issuer.jks");
        String keystorePassword = System.getProperty("keystore.password", "password");

        String truststorePath = System.getProperty("truststore.path", "trusted.jks");
        String truststorePassword = System.getProperty("truststore.password", "password");

        KeyStore keystore = KeyStore.getInstance("JKS");
        try (FileInputStream keystoreFis = new FileInputStream(keystorePath)) {
            keystore.load(keystoreFis, keystorePassword.toCharArray());
        }

        KeyStore truststore = KeyStore.getInstance("JKS");
        File truststoreFile = new File(truststorePath);
        if (truststoreFile.exists()) {
            try (FileInputStream truststoreFis = new FileInputStream(truststoreFile)) {
                truststore.load(truststoreFis, truststorePassword.toCharArray());
            }
        } else {
            truststore.load(null, null);
        }

        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();

            if (keystore.isKeyEntry(alias)) {
                Certificate[] certChain = keystore.getCertificateChain(alias);
                if (certChain != null) {
                    for (int i = 0; i < certChain.length; i++) {
                        String certAlias = alias + "-" + i;
                        truststore.setCertificateEntry(certAlias, certChain[i]);
                    }
                }
            } else if (keystore.isCertificateEntry(alias)) {
                Certificate cert = keystore.getCertificate(alias);
                truststore.setCertificateEntry(alias, cert);
            }
        }

        try (FileOutputStream truststoreFos = new FileOutputStream(truststorePath)) {
            truststore.store(truststoreFos, truststorePassword.toCharArray());
        }
    }
}
