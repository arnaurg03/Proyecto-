#!/bin/bash

# Ruta de la carpeta de cuarentena
carpeta_cuarentena="ruta de la carpeta"

# Ruta de la carpeta segura
carpeta_segura="ruta de la carpeta"

# Obtener la lista de archivos maliciosos desde la API (reemplaza 'api_comando' con el comando real)
archivos_maliciosos=$(api_comando obtener_archivos_maliciosos)

# Copiar archivos maliciosos a la carpeta de cuarentena
for archivo in $archivos_maliciosos; do
    cp "$archivo" "$carpeta_cuarentena"
done

# Obtener la lista de archivos seguros desde la API (reemplaza 'api_comando' con el comando real)
archivos_seguros=$(api_comando obtener_archivos_seguros)

# Copiar archivos seguros a la carpeta segura
for archivo in $archivos_seguros; do
    cp "$archivo" "$carpeta_segura"
done

# Ejecutar el script moverdisp.sh
ruta del siguiente script