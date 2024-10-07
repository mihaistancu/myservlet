import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.eclipse.jetty.client.api.Response;
import org.eclipse.jetty.proxy.ProxyServlet;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.Callback;

import java.io.IOException;

public class MyProxy {
    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(System.getProperty("port", "9393"));

        var server = new Server(port);
        var context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");

        var proxyServlet = new ServletHolder(new ProxyServlet() {
            @Override
            protected void service(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
                System.out.println(request.getRequestURL());
                super.service(request, response);
            }

            @Override
            protected String rewriteTarget(HttpServletRequest request) {
                return request.getRequestURL().toString();
            }

            @Override
            protected void onResponseContent(HttpServletRequest request, HttpServletResponse response, Response proxyResponse, byte[] buffer, int offset, int length, Callback callback) {
                System.out.println("proxy status: " + proxyResponse.getStatus());
                System.out.println("proxy (partial): " + new String(buffer, offset, length));

                super.onResponseContent(request, response, proxyResponse, buffer, offset, length, callback);
            }
        });

        context.addServlet(proxyServlet, "/*");
        server.setHandler(context);
        server.start();
        server.join();

    }
}
