package org.example;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;
import org.example.lib.CertificateChainFactory;
import org.example.lib.JettyServerBuilder;

import java.security.KeyStore;

import static org.example.lib.CertificateChainFactory.*;

public class MyOcsp {
    public static void main(String[] args) throws Exception {
        String rootPassword = System.getProperty("signer.password", "password");
        String rootJksPath = System.getProperty("signer.jks.path", "issuer.jks");

        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9090"));

        KeyStore signer = CertificateChainFactory.getKeyStore();
        CertificateChainFactory.load(signer, rootJksPath, rootPassword);

        Server server = new JettyServerBuilder()
                .host(host, port)
                .use("/*", new HttpServlet() {
                    @Override
                    protected void service(HttpServletRequest req, HttpServletResponse resp) {
                        try {
                            byte[] input = req.getInputStream().readAllBytes();
                            byte[] output = getOcspResponse(
                                    input,
                                    getCert(signer),
                                    getKey(signer, rootPassword),
                                    true);
                            resp.getOutputStream().write(output);
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
