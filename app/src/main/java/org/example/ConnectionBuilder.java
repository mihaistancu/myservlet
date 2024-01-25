package org.example;

import javax.net.ssl.*;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;

public class ConnectionBuilder {
    private String url;
    private KeyStore keyStore;
    private String password;
    private boolean trustAll;

    public ConnectionBuilder url(String url) {
        this.url = url;
        return this;
    }

    public ConnectionBuilder clientCert(KeyStore keyStore, String password) {
        this.keyStore = keyStore;
        this.password = password;
        return this;
    }

    public ConnectionBuilder trustAll(boolean trustAll) {
        this.trustAll = trustAll;
        return this;
    }

    public HttpsURLConnection build() {
        HttpsURLConnection connection = (HttpsURLConnection) getUrlConnection(url);

        SSLContext sslContext = getSslContext();

        KeyManager[] keyManagers = null;
        if (keyStore != null) {
            KeyManagerFactory keyManagerFactory = getKeyManagerFactory();
            initialize(keyManagerFactory, keyStore, password.toCharArray());
            keyManagers = keyManagerFactory.getKeyManagers();
        }

        TrustManager[] trustManagers = null;
        if (trustAll) {
            trustManagers = new TrustManager[]{new TrustAllTrustManager()};
        }

        initialize(sslContext, keyManagers, trustManagers);
        connection.setSSLSocketFactory(sslContext.getSocketFactory());

        setRequestMethod(connection, "POST");
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }

    public static void setRequestMethod(HttpsURLConnection connection, String method) {
        try {
            connection.setRequestMethod(method);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static URLConnection getUrlConnection(String uri) {
        try {
            return new URL(uri).openConnection();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static SSLContext getSslContext() {
        try {
            return SSLContext.getInstance("TLS");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void initialize(SSLContext sslContext, KeyManager[] keyManagers, TrustManager[] trustManagers) {
        try {
            sslContext.init(keyManagers, trustManagers, null);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static void initialize(KeyManagerFactory keyManagerFactory, KeyStore keyStore, char[] password) {
        try {
            keyManagerFactory.init(keyStore, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static KeyManagerFactory getKeyManagerFactory() {
        try {
            return KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
