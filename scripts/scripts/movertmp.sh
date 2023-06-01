#!/bin/bash

# Ruta de la carpeta inicial (USB)
carpeta_inicial="ruta de la carpeta"

# Ruta de la carpeta temporal
carpeta_temporal="ruta de la carpeta"

# Mover archivos de la carpeta inicial a la carpeta temporal
mv "$carpeta_inicial"/* "$carpeta_temporal"

# Iniciar el programa de la API (reemplaza 'programa_api' con el comando real)
programa_api

# Ejecución del script copiar.sh
echo "Ejecutando el script copiar.sh..."
./copiar.sh