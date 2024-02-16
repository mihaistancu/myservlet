package org.example;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;
import org.example.lib.CertificateChainFactory;
import org.example.lib.JettyServerBuilder;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import static org.example.lib.CertificateChainFactory.*;

public class MyCrl {

    public static void main(String[] args) throws Exception {
        String rootPassword = System.getProperty("issuer.password", "password");
        String rootJksPath = System.getProperty("issuer.path", "issuer.jks");

        String certPath = System.getProperty("cert.path", "cert.jks");

        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9092"));

        boolean isRevoked = Boolean.parseBoolean(System.getProperty("revoked", "false"));

        KeyStore root = KeyStore.getInstance("JKS");
        CertificateChainFactory.load(root, rootJksPath, rootPassword);

        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) factory.generateCertificate(new FileInputStream(certPath));

        Server server = new JettyServerBuilder()
                .host(host, port)
                .use("/*", new HttpServlet() {
                    @Override
                    protected void service(HttpServletRequest req, HttpServletResponse resp) {
                        System.out.println("crl request");

                        try {
                            X509Certificate revoked = isRevoked ? certificate : null;
                            resp.getOutputStream().write(getCrl(
                                    getCert(root),
                                    getKey(root, rootPassword),
                                    revoked));
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
