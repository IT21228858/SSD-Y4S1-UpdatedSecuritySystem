package vehicle.servlet;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;
import javax.servlet.annotation.WebServlet;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import vehicle.classes.*;
import vehicle.service.*;
/**
 * Servlet implementation class editReservation
 */
@WebServlet("/editReservation")
public class editReservation extends HttpServlet {
	private static final long serialVersionUID = 1L;
       
    /**
     * @see HttpServlet#HttpServlet()
     */
    public editReservation() {
        super();
        // TODO Auto-generated constructor stub
    }

	/**
	 * @see HttpServlet#doGet(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		// TODO Auto-generated method stub
		response.getWriter().append("Served at: ").append(request.getContextPath());
	}

	/**
	 * @see HttpServlet#doPost(HttpServletRequest request, HttpServletResponse response)
	 */
	protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		response.setContentType("text/html");
		Reservation reservation =  new Reservation();

		reservation.setId(Integer.parseInt(request.getParameter("id")));
		reservation.setDriverId(Integer.parseInt(request.getParameter("driverId")));
		reservation.setUserId(Integer.parseInt(request.getSession(false).getAttribute("userId").toString()));
		reservation.setVehicleId(Integer.parseInt(request.getParameter("vehicleId")));
		reservation.setDate(request.getParameter("date"));
		
		reservationService s = new reservationService();
		int res=s.editReservations(reservation);
		
		if(res==0) {
			RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/viewReservation.jsp");
			request.setAttribute("errors_success", 0);
			dispatcher.forward(request, response);
		}else if(res==1) {
			RequestDispatcher dispatcher = getServletContext().getRequestDispatcher("/viewReservation.jsp");
			request.setAttribute("errors_success", 1);
			dispatcher.forward(request, response);
		}
	}

}
