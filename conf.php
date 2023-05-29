<?php
define('USER', 'root');
define('PASSWORD', '0000');
define('HOST', 'localhost');
define('DATABASE', 'db_users');
try {
    $connection = new PDO("mysql:host=".HOST.";dbname=".DATABASE, USER, PASSWORD);
} catch (PDOException $e) {
    exit("Error: " . $e->getMessage());
}
?>