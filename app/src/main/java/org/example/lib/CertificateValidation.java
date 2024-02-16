package org.example.lib;

import java.security.KeyStore;
import java.security.cert.*;

public class CertificateValidation {
    public static void validate(X509Certificate certificate, KeyStore trustStore, boolean checkRevocation) {
        try {
            CertPathBuilder builder = CertPathBuilder.getInstance("PKIX");

            X509CertSelector selector = new X509CertSelector();
            selector.setCertificate(certificate);

            PKIXBuilderParameters params = new PKIXBuilderParameters(trustStore, selector);
            params.setRevocationEnabled(checkRevocation);
            builder.build(params);

        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }
}
