package org.example.lib;

import java.security.KeyStore;
import java.security.cert.*;
import java.util.EnumSet;

public class CertificateValidation {
    public static void validate(CertPath certPath, KeyStore trustStore, boolean checkRevocation) {
        try {
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            PKIXRevocationChecker checker = (PKIXRevocationChecker) validator.getRevocationChecker();
            checker.setOptions(EnumSet.of(PKIXRevocationChecker.Option.ONLY_END_ENTITY));

            PKIXParameters params = new PKIXParameters(trustStore);
            params.setRevocationEnabled(checkRevocation);
            params.addCertPathChecker(checker);

            validator.validate(certPath, params);

        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }
}
