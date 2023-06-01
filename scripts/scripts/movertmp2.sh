#!/bin/bash

# Ruta de la carpeta temporal
temp_folder="/ruta/a/la/carpeta/temporal"

# Función para mover los archivos de la carpeta USB a la carpeta temporal
move_files() {
  usb_folder="$1"

  # Comprobación de existencia de la carpeta temporal
  if [ ! -d "$temp_folder" ]; then
    echo "La carpeta temporal no existe. Creando la carpeta..."
    mkdir "$temp_folder"
    if [ $? -ne 0 ]; then
      echo "Error al crear la carpeta temporal."
      exit 1
    fi
    echo "Carpeta temporal creada correctamente."
  fi

  # Mover archivos de la carpeta USB a la carpeta temporal
  mv "$usb_folder"/* "$temp_folder"

  # Verificación de éxito
  if [ $? -eq 0 ]; then
    echo "Los archivos se han movido correctamente a la carpeta temporal."
  else
    echo "Hubo un error al mover los archivos a la carpeta temporal."
    exit 1
  fi

  # Ejecución del script copiar.sh
  echo "Ejecutando el script copiar.sh..."
  ./copiar.sh

  # Verificación de éxito
  if [ $? -eq 0 ]; then
    echo "El script copiar.sh se ha ejecutado correctamente."
  else
    echo "Hubo un error al ejecutar el script copiar.sh."
    exit 1
  fi
}

# Función para manejar el evento de conexión del USB
handle_usb_connect() {
  usb_folder="$1"
  echo "Dispositivo USB conectado. Carpeta detectada: $usb_folder"
  move_files "$usb_folder"
}

# Función para manejar el evento de desconexión del USB
handle_usb_disconnect() {
  echo "Dispositivo USB desconectado."
}

# Monitoreo de eventos de conexión y desconexión del USB
udevadm monitor --udev -s block -k -p /devices | while read -r line; do
  if echo "$line" | grep -q "add"; then
    usb_folder=$(echo "$line" | awk '{print $NF}')
    handle_usb_connect "$usb_folder"
  elif echo "$line" | grep -q "remove"; then
    handle_usb_disconnect
  fi
done
