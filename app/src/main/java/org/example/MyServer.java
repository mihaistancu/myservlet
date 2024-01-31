package org.example;

import org.eclipse.jetty.server.Server;
import org.example.lib.CertificateChainFactory;
import org.example.lib.JettyServerBuilder;

import java.security.KeyStore;

public class MyServer {

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");
        String jksPath = System.getProperty("jks.path", "server.jks");
        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9090"));
        boolean trustAll = Boolean.parseBoolean(System.getProperty("trustAll", "true"));

        KeyStore tls = CertificateChainFactory.getKeyStore("JKS");
        CertificateChainFactory.load(tls, jksPath, password);

        var servlet = new MyServlet();

        Server server = new JettyServerBuilder()
                .host(host, port)
                .secure(tls, password, trustAll)
                .use("/*", servlet)
                .build();

        server.start();
    }
}