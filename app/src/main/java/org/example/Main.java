package org.example;

import org.eclipse.jetty.server.Server;

import javax.net.ssl.HttpsURLConnection;
import java.security.KeyStore;
import java.util.List;

public class Main {

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");
        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9090"));
        boolean trustAll = Boolean.parseBoolean(System.getProperty("trustAll", "true"));
        String url = "https://" + host + ":" + port + "/";

        KeyStore tls = CertificateFactory.createKeyStore(password);

        List<String> options = List.of(args);

        if (options.contains("server")) {
            var servlet = new MyServlet();

            Server server = new JettyServerBuilder()
                    .host(host, port)
                    .secure(tls, password, trustAll)
                    .use("/*", servlet)
                    .build();

            server.start();
        }
        else if (options.contains("client")) {
            HttpsURLConnection connection = new ConnectionBuilder()
                    .url(url)
                    .clientCert(tls, password)
                    .trustAll(trustAll)
                    .build();

            connection.getInputStream().transferTo(System.out);
        }
    }
}