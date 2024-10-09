import lib.MyServlet;
import org.eclipse.jetty.server.Server;
import lib.CertificateChainFactory;
import lib.JettyServerBuilder;

import java.security.KeyStore;

public class MyServer {

    public static void main(String[] args) throws Exception {
        String password = System.getProperty("password", "password");
        String jksPath = System.getProperty("jks.path", "cert.jks");
        String host = System.getProperty("host", "0.0.0.0");
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