import pandas as pd

# Reemplaza con la ruta de tu archivo
ruta_xlsb = "C:\\Users\\Ruben\\Desktop\\licenciascc.xlsb"

# Cargar el archivo XLSB con LICENCIA como texto
df = pd.read_excel(ruta_xlsb, sheet_name=None, engine="pyxlsb", dtype={"LICENCIA": str})

# Iterar sobre cada hoja
for sheet_name, data in df.items():
    # 🔹 Asegurar que LICENCIA tenga ceros a la izquierda
    if "LICENCIA" in data.columns:
        data["LICENCIA"] = data["LICENCIA"].apply(lambda x: f"{int(x):05}" if pd.notna(x) else x)

    # Guardar como CSV
    data.to_csv(f"{sheet_name}.csv", index=False, encoding='utf-8')

print("Conversión completada 🎉")
