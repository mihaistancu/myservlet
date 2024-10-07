package lib;

import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.time.Instant;

public class MyServlet extends HttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) {
        System.out.println("service");
        try {
            res.getOutputStream().print(Instant.now().toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
