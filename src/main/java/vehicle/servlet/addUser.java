package vehicle.servlet;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.MultipartConfig;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vehicle.classes.User;
import vehicle.service.userService;
import vehicle.utils.PasswordUtils;
import org.apache.commons.text.StringEscapeUtils;

/**
 * Servlet implementation class addUser
 */
@WebServlet("/addUser")
@MultipartConfig
public class addUser extends HttpServlet {
    private static final long serialVersionUID = 1L;

    /**
     * @see HttpServlet#HttpServlet()
     */
    public addUser() {
        super();
    }

    /**
     * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {

        // Generate a random CSRF token
        String csrfToken = new BigInteger(130, new SecureRandom()).toString(32);

        // Store the CSRF token in the session
        request.getSession().setAttribute("csrfToken", csrfToken);

        System.out.println("Generated CSRF token in doGet: " + csrfToken);

        // Forward to the JSP page and include the CSRF token
        request.setAttribute("csrfToken", csrfToken);
        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/register.jsp");
        dispatcher.forward(request, response);
    }

    /**
     * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
     */
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html");

        // Retrieve the CSRF token from the request and the session
        String csrfToken = request.getParameter("csrfToken");
        String sessionToken = (String) request.getSession().getAttribute("csrfToken");

        // Debugging: Print the CSRF token from session and request
        System.out.println("CSRF token from session in doPost: " + sessionToken);
        System.out.println("CSRF token from request in doPost: " + csrfToken);

        if (csrfToken == null || !csrfToken.equals(sessionToken)) {
            // CSRF token is invalid, reject the request
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
            return;
        }

        // Get and sanitize input parameters
        String name = StringEscapeUtils.escapeHtml4(request.getParameter("name")); // XSS prevention
        String address = StringEscapeUtils.escapeHtml4(request.getParameter("address"));
        String email = request.getParameter("email");
        String nic = StringEscapeUtils.escapeHtml4(request.getParameter("nic"));
        String photo = request.getParameter("photo"); // Assuming this is a file path or URL; validate it
        String password = request.getParameter("password");

        // Input validation for email and NIC
        if (!isValidEmail(email) || !isValidNIC(nic)) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid input");
            return;
        }

        // Hash the password before storing it
        String hashedPassword = PasswordUtils.hashPassword(password);

        // Proceed with user creation
        User user = new User();
        user.setName(name);
        user.setAddress(address);
        user.setEmail(email);
        user.setNic(nic);
        user.setPhoto(photo);
        user.setPassword(hashedPassword); // Store hashed password
        user.setPrivilege(0);

        userService s = new userService();
        int res = s.addUser(user);

        // Remove the CSRF token from the session after successful form submission
        request.getSession().removeAttribute("csrfToken");

        // Handle the result
        if (res == 0) {
            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/register.jsp");
            request.setAttribute("errors_success", 0);
            dispatcher.forward(request, response);
        } else if (res == 1) {
            RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/register.jsp");
            request.setAttribute("errors_success", 1);
            dispatcher.forward(request, response);
        }

        if (sessionToken == null) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Session expired or invalid CSRF token");
            return;
        }
    }

    private boolean isValidEmail(String email) {
        return email != null && email.matches("^[A-Za-z0-9+_.-]+@(.+)$");
    }

    private boolean isValidNIC(String nic) {
        return nic != null && nic.matches("^[0-9]{9}[VvXx]$"); // Example NIC validation
    }
}
