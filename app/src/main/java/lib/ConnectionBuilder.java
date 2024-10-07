package lib;

import javax.net.ssl.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyStore;

public class ConnectionBuilder {
    private String url;
    private KeyStore keyStore;
    private String password;
    private boolean trustAll;
    private String method = "POST";

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

    public ConnectionBuilder method(String method) {
        this.method = method;
        return this;
    }

    public HttpURLConnection build() {
        HttpURLConnection connection = (HttpURLConnection) getUrlConnection(url);

        if (url.startsWith("https")) {
            HttpsURLConnection tlsConnection = (HttpsURLConnection) connection;
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
            tlsConnection.setSSLSocketFactory(sslContext.getSocketFactory());
        }

        setRequestMethod(connection, method);
        connection.setDoInput(true);
        connection.setDoOutput(true);
        return connection;
    }

    public static void setRequestMethod(HttpURLConnection connection, String method) {
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
