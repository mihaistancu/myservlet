import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.server.Server;
import lib.JettyServerBuilder;

import java.io.FileInputStream;

public class MyAia {

    public static void main(String[] args) throws Exception {
        String host = System.getProperty("host", "localhost");
        int port = Integer.parseInt(System.getProperty("port", "9093"));

        String filePath = System.getProperty("file", "file");

        Server server = new JettyServerBuilder()
                .host(host, port)
                .use("/*", new HttpServlet() {
                    @Override
                    protected void service(HttpServletRequest req, HttpServletResponse resp) {
                        System.out.println("aia request");

                        try (var input = new FileInputStream(filePath)){
                            input.transferTo(resp.getOutputStream());
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
