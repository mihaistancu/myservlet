package org.example;

import jakarta.servlet.annotation.WebServlet;
import lib.MyServlet;

@WebServlet("/*")
public class MyWrapperServlet extends MyServlet {

}
