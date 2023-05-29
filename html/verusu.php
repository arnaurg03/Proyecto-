<?php
// Datos de conexión a la base de datos
$host = 'localhost';
$db = 'db_users';
$user = 'root';
$password = '0000';

// Conexión a la base de datos
$conexion = new mysqli($host, $user, $password, $db);

// Verificar si hay error de conexión
if ($conexion->connect_error) {
    die('Error de conexión: ' . $conexion->connect_error);
}

// Consulta para obtener los usuarios registrados
$sql = "SELECT * FROM usuarios";
$resultado = $conexion->query($sql);

// Verificar si hay resultados
if ($resultado->num_rows > 0) {
    // Recorrer los resultados y mostrar los datos
    while ($fila = $resultado->fetch_assoc()) {
        echo 'Nombre: ' . $fila['nombre'] . '<br>';
        echo 'Email: ' . $fila['email'] . '<br>';
        echo 'Contraseña: ' . $fila['password'] . '<br>';
        echo '--------------------------<br>';
    }
} else {
    echo 'No se encontraron usuarios registrados.';
}

// Cerrar la conexión
$conexion->close();
?>