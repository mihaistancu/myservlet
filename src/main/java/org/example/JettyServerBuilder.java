package org.example;


import jakarta.servlet.http.HttpServlet;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.List;

public class JettyServerBuilder {
    private KeyStore keyStore;
    private String keyStorePassword;
    private String hostname = "localhost";
    private int port = 443;
    private List<ServletInfo> servletInfoList = new ArrayList<>();
    private boolean isTlsEnabled = false;
    private boolean trustAllClients = false;

    private record ServletInfo(String path, HttpServlet servlet) {
    }

    public JettyServerBuilder host(String hostname, int port) {
        this.hostname = hostname;
        this.port = port;
        return this;
    }

    public JettyServerBuilder secure(KeyStore keyStore, String password, boolean trustAllClients) {
        this.isTlsEnabled = true;
        this.trustAllClients = trustAllClients;
        this.keyStore = keyStore;
        this.keyStorePassword = password;
        return this;
    }

    public JettyServerBuilder use(String path, HttpServlet servlet) {
        this.servletInfoList.add(new ServletInfo(path, servlet));
        return this;
    }

    public Server build() {
        Server server = new Server();

        ServerConnector connector;

        if (isTlsEnabled) {
            HttpConfiguration httpConfig = new HttpConfiguration();
            httpConfig.addCustomizer(new SecureRequestCustomizer());

            HttpConnectionFactory http11 = new HttpConnectionFactory(httpConfig);

            SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
            SSLContext sslContext = getSslContext();

            KeyManagerFactory keyManagerFactory = getKeyManagerFactory();
            initialize(keyManagerFactory, keyStore, keyStorePassword.toCharArray());
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            if (trustAllClients) {
                TrustManager[] trustManagers = new TrustManager[]{new TrustAllTrustManager()};
                initialize(sslContext, keyManagers, trustManagers);
            }
            else {
                initialize(sslContext, keyManagers, null);
            }

            sslContextFactory.setSslContext(sslContext);
            sslContextFactory.setNeedClientAuth(true);

            SslConnectionFactory tls = new SslConnectionFactory(sslContextFactory, http11.getProtocol());

            connector = new ServerConnector(server, tls, http11);
        } else {
            connector = new ServerConnector(server);
        }

        connector.setHost(hostname);
        connector.setPort(port);

        server.addConnector(connector);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);

        for (ServletInfo servletInfo : servletInfoList) {
            context.addServlet(new ServletHolder(servletInfo.servlet), servletInfo.path);
        }
        context.setContextPath("/");

        server.setHandler(context);

        return server;
    }

    public static SSLContext getSslContext() {
        try {
            return SSLContext.getInstance("TLS");
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

    public static void initialize(KeyManagerFactory keyManagerFactory, KeyStore keyStore, char[] password) {
        try {
            keyManagerFactory.init(keyStore, password);
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
}