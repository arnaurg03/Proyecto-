<?php
$servername = "localhost";
$username = "web";
$password = "web";

// Crea la conexión
$conn = new mysqli($servername, $username, $password,"db_users");


// Verifica la conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Check if the user has submitted the form
if (isset($_POST['usuario']) && isset($_POST['password'])) {
    // Get the submitted username and password
    $username = $_POST['usuario'];
    $password = $_POST['password'];

    // Create a query to check if the user exists in the database
    $query = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
    

    $results = mysqli_query($db, $query);

    // Check if the user exists
    if (mysqli_num_rows($results) == 1) {
        // The user exists, start a session and redirect to the home page
        session_start();
        $_SESSION['username'] = $username;
        echo "USUARIO CREADO CORRECTAMENTE $username";
        header('location index.php');
    } else {
        // The user does not exist, show an error message
        echo "Usuario ya creado";
    }
}
?>


<!-- Define que el documento esta bajo el estandar de HTML 5 -->
<!doctype html>

<!-- Representa la raíz de un documento HTML o XHTML. Todos los demás elementos deben ser descendientes de este elemento. -->
<html lang="es">
    
    <head>
        
        <meta charset="utf-8">
        
        <title> Formulario de Acceso </title>    
        
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        
        <meta name="author" content="Videojuegos & Desarrollo">
        <meta name="description" content="Muestra de un formulario de acceso en HTML y CSS">
        <meta name="keywords" content="Formulario Acceso, Formulario de LogIn">
        
        <link href="https://fonts.googleapis.com/css?family=Nunito&display=swap" rel="stylesheet"> 
        <link href="https://fonts.googleapis.com/css?family=Overpass&display=swap" rel="stylesheet">
        
        <!-- Link hacia el archivo de estilos css -->
        <link rel="stylesheet" href="/login.css">
        
        <style type="text/css">
            
        </style>
        
        <script type="text/javascript">
        
        </script>
        
    </head>
    
    <body>
        
        <div id="contenedor">
            <div id="central">
                <div id="login">
                    <div class="titulo">
                        Bienvenido
                    </div>
                    <form id="loginform">
                        <input type="text" name="usuario" placeholder="Usuario" required>
                        
                        <input type="password" placeholder="Contraseña" name="password" required>
                        
                        <button type="submit" title="Ingresar" name="Ingresar">Sign In</button>
                    </form>
                    
                </div>
                <div class="inferior">
                    <a href="index.php">Volver</a>
                </div>
            </div>
        </div>
            
    </body>
</html>