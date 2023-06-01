#!/bin/bash

# Ruta de la carpeta temporal
temp_folder="ruta de la carpeta"

# Comprobación de existencia de la carpeta temporal
if [ ! -d "$temp_folder" ]; then
  echo "La carpeta temporal no existe."
  exit 1
fi

# Eliminación de todo el contenido de la carpeta temporal
rm -rf "$temp_folder"/*

# Verificación de éxito
if [ $? -eq 0 ]; then
  echo "El contenido de la carpeta temporal ha sido eliminado correctamente."
else
  echo "Hubo un error al eliminar el contenido de la carpeta temporal."
fi
