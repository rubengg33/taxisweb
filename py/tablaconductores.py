import pandas as pd
import mysql.connector
import csv

# Configurar conexión a MySQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Ovejita123",
    database="controlconductores",
    port=3306
)

cursor = conn.cursor()

# Cargar CSV correctamente con el delimitador ";"
df = pd.read_csv(
    "C:/Users/Ruben/Documents/taxi/taxisweb/conductores.csv",
    dtype=str,  # Leer todo como string para evitar NaN
    delimiter=";",  # Usar punto y coma como delimitador
    quoting=csv.QUOTE_MINIMAL,  # Manejo básico de comillas
    skipinitialspace=True  # Evita espacios extra tras separadores
)

# Renombrar columnas si es necesario
df.columns = ["nombre_apellidos", "dni", "direccion", "codigo_postal", "email", "numero_seguridad_social"]

# 🔹 Limpiar campos: eliminar espacios extra al inicio y fin
df = df.applymap(lambda x: x.strip() if isinstance(x, str) else x)

# Reemplazar valores nulos o no válidos por cadenas vacías
df = df.fillna("").replace(["nan", "NaN", "None"], "")

# Insertar datos en la tabla
for _, row in df.iterrows():
    cursor.execute("""
        INSERT INTO conductores (nombre_apellidos, dni, direccion, codigo_postal, email, numero_seguridad_social)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, tuple(row))

# Confirmar cambios
conn.commit()
conn.close()

print("🚀 Importación completada correctamente")
