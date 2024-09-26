<%@ page language="java" contentType="text/html; charset=ISO-8859-1" pageEncoding="ISO-8859-1"%>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Vehicle Reservation System</title>

    <script src="assets/js/bootstrap.min.js"></script>
    <script src="assets/js/croppie.js"></script>
    <link rel="stylesheet" href="assets/css/croppie.css" />
    <link href="assets/css/bootstrap.min.css" rel="stylesheet">
    <script src="assets/js/sweetalert.min.js"></script>

    <!-- Updated script imports -->
    <script src="https://ajax.googleapis.com/ajax/libs/jquery/1.10.2/jquery.min.js" 
        integrity="sha384-rgNqjTW0vJcRRewFiq9X9ZcvSGlgiK1IgAo/TUKfD1ENslJTOcA8NiRGVfi7vlwx" 
        crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-validate/1.19.0/jquery.validate.min.js" 
        integrity="sha384-Q6dYfGe5fpe5EotM9z2pTqzcb0khRnhgml1/4OB8fKkPiUPjb/Sbb2fKM7cUjP5u" 
        crossorigin="anonymous"></script>

    <style type="text/css">
        .my-error-class {
            color: red;
        }
        .my-valid-class {
            color: green;
        }
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-lg navbar-light bg-light">
        <div class="container">
            <a class="navbar-brand" href="profileServlet">Vehicle Reservation System</a>
            <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="Toggle navigation">
                <span class="navbar-toggler-icon"></span>
            </button>

            <div class="collapse navbar-collapse" id="navbarSupportedContent">
                <ul class="navbar-nav ml-auto">
                    <% if(session.getAttribute("userEmail") == null){ %>
                    <li class="nav-item">
                        <a class="nav-link" href="login.jsp">Login</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="register.jsp">Register</a>
                    </li>
                    <% } else { %>
                    <li class="nav-item">
                        <a class="nav-link" href="logoutServlet">Logout</a>
                    </li>
                    <% } %>
                </ul>
            </div>
        </div>
    </nav>

    <div class="container">
        <br>
        <main class="login-form">
            <div class="row justify-content-center">
                <div class="col-md-8">
                    <div class="card">
                        <div class="card-header">Login</div>
                        <div class="card-body">
                            <% if(request.getAttribute("errors_success") != null) {
                                if(request.getAttribute("errors_success").equals(1)) { %>
                                <div class="alert alert-success">Successful!</div>
                                <% } else { %>
                                <div class="alert alert-danger">Unsuccessful!</div>
                                <% } 
                            } %>

                            <form action="loginServlet" method="post">
                                <div class="form-group row">
                                    <label for="email_address" class="col-md-4 col-form-label text-md-right">Email</label>
                                    <div class="col-md-6">
                                        <input type="text" id="email" class="form-control" name="email">
                                    </div>
                                </div>

                                <div class="form-group row">
                                    <label for="password" class="col-md-4 col-form-label text-md-right">Password</label>
                                    <div class="col-md-6">
                                        <input type="password" id="password" class="form-control" name="password">
                                    </div>
                                </div>

                                <input type="hidden" name="csrfToken" value='${csrfToken}'>

                                <div class="col-md-6 offset-md-4">
                                    <button type="submit" class="btn btn-primary">Login</button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <script>
        window.onload = function() {
            var x = ${sessionScope.errors_success };
            if ("1" == x) {
                swal("Success!", "Your Account Has Been Registered. You Can Login Now!", "success");
                <% session.setAttribute("errors_success", null); %>
            } else if ("2" == x) {
                swal({
                    title: "Error",
                    text: "Your Password Or Email Is Wrong!",
                    icon: "warning",
                    dangerMode: true,
                });
                <% session.setAttribute("errors_success", null); %>
            } else if ("3" == x) {
                swal({
                    title: "Error",
                    text: "Registration Unsuccessful!",
                    icon: "warning",
                    dangerMode: true,
                });
                <% session.setAttribute("errors_success", null); %>
            }
        }
    </script>
</body>
</html>
