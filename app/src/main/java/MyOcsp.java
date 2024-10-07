import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.jetty.server.Server;
import lib.CertificateChainFactory;
import lib.JettyServerBuilder;

import java.security.KeyStore;
import java.security.Security;
import java.util.Base64;

import static lib.CertificateChainFactory.*;

public class MyOcsp {
    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        String rootPassword = System.getProperty("signer.password", "password");
        String rootJksPath = System.getProperty("signer.jks.path", "signer.jks");

        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9091"));

        boolean includeCertInResponse = Boolean.parseBoolean(System.getProperty("includeCertInResponse", "true"));
        String status = System.getProperty("status", "good");

        KeyStore signer = CertificateChainFactory.getKeyStore("JKS");
        CertificateChainFactory.load(signer, rootJksPath, rootPassword);

        Server server = new JettyServerBuilder()
                .host(host, port)
                .use("/*", new HttpServlet() {
                    @Override
                    protected void service(HttpServletRequest req, HttpServletResponse resp) {
                        try {
                            System.out.println(req.getPathInfo());

                            byte[] input = Base64.getDecoder().decode(req.getPathInfo().substring(1));
                            byte[] output = getOcspResponse(
                                    input,
                                    getCert(signer),
                                    getKey(signer, rootPassword),
                                    includeCertInResponse,
                                    status);
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
