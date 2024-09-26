package vehicle.servlet;

import java.io.IOException;
import java.util.UUID;
import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vehicle.classes.User;
import vehicle.service.userService;

/**
 * Servlet implementation class getUser
 */
@WebServlet("/getUser")
public class getUser extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public getUser() {
        super();
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// Check if session exists
		if (request.getSession(false) == null || request.getSession(false).getAttribute("userId") == null) {
			// Handle the case where the session or userId is null (e.g., redirect to login page)
			System.out.println("Session or userId is null, redirecting to login page.");
			response.sendRedirect("login.jsp");
			return;
		}

	    // Generate CSRF token and store it in session
	    String csrfToken = UUID.randomUUID().toString();  // Generate a unique token
	    request.getSession().setAttribute("csrfToken", csrfToken);  // Store in session

	    // SOP for CSRF token generation
	    System.out.println("Generated CSRF token in doGet: " + csrfToken);
	    
	    // Fetch user data
		response.setContentType("text/html");
		userService c = new userService();
		User user = c.getUser(Integer.parseInt(request.getSession(false).getAttribute("userId").toString()));
		
		// Set user and CSRF token as request attributes to pass to JSP
		request.setAttribute("user", user);
		request.setAttribute("csrfToken", csrfToken);

		// Forward to editUser.jsp
		RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/editUser.jsp");
		dispatcher.forward(request, response);
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
	    // Validate CSRF token
	    String sessionToken = (String) request.getSession().getAttribute("csrfToken");
	    String formToken = request.getParameter("csrfToken");

	    // SOP to print the tokens during validation
	    System.out.println("Session CSRF Token: " + sessionToken);
	    System.out.println("Form CSRF Token: " + formToken);

	    if (sessionToken == null || !sessionToken.equals(formToken)) {
	        // CSRF token is invalid, reject the request
	        System.out.println("CSRF token validation failed!");  // SOP for failed validation
	        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid CSRF token");
	        return;
	    }
	    
	    // If CSRF token is valid, continue processing the request
	    System.out.println("CSRF token validation succeeded!");  // SOP for successful validation

	    // Fetch and update the user based on the submitted data
	    userService c = new userService();
	    User user = c.getUser(Integer.parseInt(request.getSession(false).getAttribute("userId").toString()));

	    user.setName(request.getParameter("name"));
	    user.setAddress(request.getParameter("address"));
	    user.setEmail(request.getParameter("email"));
	    user.setNic(request.getParameter("nic"));
	    user.setPassword(request.getParameter("password"));  // Remember to hash the password for security!

	    // Save the updated user
//	    c.updateUser(user);

	    // Redirect after successful form submission
	    response.sendRedirect("profileServlet");

	    // Optionally, remove the CSRF token after successful form submission
	    request.getSession().removeAttribute("csrfToken");
	}
}
