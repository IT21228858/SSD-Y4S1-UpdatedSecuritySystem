package vehicle.servlet;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import vehicle.service.loginService;

/**
 * Servlet implementation class loginServlet
 */
@WebServlet("/loginServlet")
public class loginServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public loginServlet() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		   // Set the X-Frame-Options header to prevent clickjacking
		 response.setHeader("X-Frame-Options", "DENY");

		
		// Generate a random CSRF token
	    String csrfToken = new BigInteger(130, new SecureRandom()).toString(32);

	    // Store the CSRF token in the session
	    request.getSession().setAttribute("csrfToken", csrfToken);
	    
	    System.out.println("Generated CSRF token in doGet: " + csrfToken);
	    
	    // Forward to the JSP page and include the CSRF token
	    request.setAttribute("csrfToken", csrfToken);
	    RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/login.jsp");
	    dispatcher.forward(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html;charset=UTF-8");
		// Set the X-Frame-Options header to prevent clickjacking
	    response.setHeader("X-Frame-Options", "DENY");
		 // Retrieve CSRF token from the request and session
	    String csrfToken = request.getParameter("csrfToken");
	    String sessionToken = (String) request.getSession().getAttribute("csrfToken");

	    // Validate CSRF token
	    if (csrfToken == null || !csrfToken.equals(sessionToken)) {
	        // CSRF token is invalid, reject the request
	        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
	        return;
	    }

	    // Sanitize and validate user inputs
	    String email = sanitizeInput(request.getParameter("email")); // Sanitize email
	    String password = sanitizeInput(request.getParameter("password")); // Sanitize password

	    if (!isValidEmail(email)) {
	        response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Invalid email format");
	        return;
	    }
	    

	    // Proceed with login validation using the sanitized email and password
	    loginService login = new loginService();
	    int id = login.login(email, password); 

	    HttpSession session = request.getSession();

	    // Handle login outcomes
	    if (login.getSuccess() == 0) {
	        // Invalid credentials
	        session.setAttribute("userEmail", email);
	        request.setAttribute("errors_success", 0);
	        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/login.jsp");
	        dispatcher.forward(request, response);
	    } else if (login.getSuccess() == 1) {
	        // Successful login for a regular user
	        session.setAttribute("userEmail", email);
	        session.setAttribute("userId", id);
	        request.setAttribute("errors_success", 1);
	        request.getSession().removeAttribute("csrfToken");
	        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/profile.jsp");
	        dispatcher.forward(request, response);
	    } else if (login.getSuccess() == 2) {
	        // Successful login for an admin
	        session.setAttribute("userEmail", email);
	        session.setAttribute("userId", id);
	        request.setAttribute("errors_success", 1);
	        request.getSession().removeAttribute("csrfToken");
	        RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/admin.jsp");
	        dispatcher.forward(request, response);
	    }

	    if (sessionToken == null) {
	        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Session expired or invalid CSRF token");
	        return;
	    }
	}
	
	private String sanitizeInput(String input) {
	    if (input == null) {
	        return null;
	    }
	    // Escape special characters
	    return input.replaceAll("[^A-Za-z0-9@.]", "");
	}
	
	private boolean isValidEmail(String email) {
	    return email != null && email.length() <= 255 && email.matches("^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+$");
	}

	private boolean isValidPassword(String password) {
	    return password != null && password.length() >= 8 && password.length() <= 20; // Length constraints on password
	}
	
	private void setSameSiteCookieAttribute(HttpServletResponse response, HttpSession session) {
	    // Get the session ID and create a new cookie with the session ID
	    String sessionId = session.getId();
	    Cookie sessionCookie = new Cookie("JSESSIONID", sessionId);

	    // Set SameSite attribute to Strict, as well as other secure cookie settings
	    sessionCookie.setPath("/");
	    sessionCookie.setHttpOnly(true);
	    sessionCookie.setSecure(true);  // Ensure HTTPS is used
	    sessionCookie.setMaxAge(30 * 60); // Set session expiration time (30 minutes)
	    sessionCookie.setComment("SameSite=Strict"); // Manually add SameSite=Strict

	    // Add the cookie to the response
	    response.addCookie(sessionCookie);
	}
	

}
