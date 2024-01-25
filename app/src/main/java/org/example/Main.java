package org.example;

import java.security.KeyStore;
import java.util.List;

public class Main {

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");
        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9090"));
        boolean trustAll = Boolean.parseBoolean(System.getProperty("trustAll", "true"));

        List<String> options = List.of(args);

        if (options.contains("server")) {
            var servlet = new MyServlet();

            KeyStore tls = CertificateFactory.createKeyStore(password);

            var server = new JettyServerBuilder()
                    .host(host, port)
                    .secure(tls, password, trustAll)
                    .use("/*", servlet)
                    .build();

            server.start();
        }
        else if (options.contains("client")) {

        }
    }
}