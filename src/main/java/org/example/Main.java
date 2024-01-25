package org.example;

public class Main {
    public static void main(String[] args) {
        var servlet = new MyServlet();
        servlet.service(null, null);
    }
}