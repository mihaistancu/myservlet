package org.example;

import javax.net.ssl.X509TrustManager;
import java.security.cert.X509Certificate;

public class TrustAllTrustManager implements X509TrustManager {
    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) {
        // Trust all client certificates
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) {
        // Trust all server certificates
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}
