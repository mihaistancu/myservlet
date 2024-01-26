package org.example;

import org.eclipse.jetty.server.Server;

import java.security.KeyStore;

public class MyServer {

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");
        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9090"));
        boolean trustAll = Boolean.parseBoolean(System.getProperty("trustAll", "true"));

        KeyStore tls = CertificateFactory.createKeyStore(password);

        var servlet = new MyServlet();

        Server server = new JettyServerBuilder()
                .host(host, port)
                .secure(tls, password, trustAll)
                .use("/*", servlet)
                .build();

        server.start();
    }
}