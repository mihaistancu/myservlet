package org.example;

import jakarta.servlet.annotation.WebServlet;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.time.Instant;

@WebServlet("/*")
public class MyServlet extends HttpServlet {
    @Override
    protected void service(HttpServletRequest req, HttpServletResponse res) {
        System.out.println("service");
        try {
            res.getOutputStream().print(Instant.now().toString());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
