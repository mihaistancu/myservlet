package org.example;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;
import org.example.lib.CertificateChainFactory;
import org.example.lib.JettyServerBuilder;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;

import static org.example.lib.CertificateChainFactory.*;

public class MyCrl {

    public static void main(String[] args) throws Exception {
        String rootPassword = System.getProperty("issuer.password", "password");
        String rootJksPath = System.getProperty("issuer.jks.path", "issuer.jks");

        String certPassword = System.getProperty("cert.password", "password");
        String certJksPath = System.getProperty("cert.jks.path", "cert.jks");

        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9090"));

        KeyStore root = CertificateChainFactory.getKeyStore("JKS");
        CertificateChainFactory.load(root, rootJksPath, rootPassword);

        KeyStore cert = CertificateChainFactory.getKeyStore("JKS");
        CertificateChainFactory.load(cert, certJksPath, certPassword);

        Server server = new JettyServerBuilder()
                .host(host, port)
                .use("/*", new HttpServlet() {
                    @Override
                    protected void service(HttpServletRequest req, HttpServletResponse resp) {
                        if (!Files.exists(Path.of("revoked"))) {
                            return;
                        }
                        try {
                            resp.getOutputStream().write(getCrl(
                                    getCert(root),
                                    getKey(root, rootPassword),
                                    getCert(cert)));
                        }
                        catch (Exception e) {
                            throw new RuntimeException(e);
                        }
                    }
                })
                .build();

        server.start();
    }
}
