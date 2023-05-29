<?php
$servername = "localhost";
$username = "web";
$password = "web";

// Crea la conexión
$conn = new mysqli($servername, $username, $password);

// Verifica la conexión
if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Crea la base de datos
$sql = "CREATE DATABASE db_users";
if ($conn->query($sql) === TRUE) {
    echo "Base de datos creada con éxito";
} else {
    echo "Error al crear la base de datos: " . $conn->error;
}

// Selecciona la base de datos
mysqli_select_db($conn,"db_users");

// Crea la tabla
$sql = "CREATE TABLE users (
id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
username VARCHAR(30) NOT NULL,
password VARCHAR(30) NOT NULL
)";

if ($conn->query($sql) === TRUE) {
    echo "Tabla creada con éxito";
} else {
    echo "Error al crear la tabla: " . $conn->error;
}

$conn->close();
?>
