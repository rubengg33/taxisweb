import pandas as pd
import mysql.connector

# Configura la conexión a MySQL
conn = mysql.connector.connect(
    host="localhost",
    user="root",
    password="Ovejita123",
    database="controlconductores",
    port=3306
)

cursor = conn.cursor()

# Cargar CSV en Pandas
df = pd.read_csv("C:/Users/Ruben/Documents/taxi/taxisweb/Licencias.csv", dtype={"LICENCIA": str})

# Renombrar columnas si es necesario
df.columns = ["LICENCIA", "DNI", "NOMBRE_APELLIDOS", "MATRICULA", "MARCA_MODELO", "EMAIL", "NUMERO_PATRONAL"]

# 🔹 Asegurar que LICENCIA tenga ceros a la izquierda y sea STRING
df["LICENCIA"] = df["LICENCIA"].apply(lambda x: f"{int(x):05}" if pd.notna(x) else None)

# Reemplazar NaN con None para evitar errores en MySQL
df = df.where(pd.notna(df), None).astype(object)

# Insertar datos en la tabla
for _, row in df.iterrows():
    cursor.execute("""
        INSERT INTO licencias (LICENCIA, DNI, NOMBRE_APELLIDOS, MATRICULA, MARCA_MODELO, EMAIL, NUMERO_PATRONAL) 
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, tuple(row.values))

# Confirmar cambios
conn.commit()
conn.close()

print("Importación completada 🚀")
