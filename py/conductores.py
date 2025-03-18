import pandas as pd

# Ruta del archivo XLSB
ruta_xlsb = "C:\\Users\\Ruben\\Desktop\\conductores.xlsb"

# Cargar todas las hojas del XLSB
df_dict = pd.read_excel(ruta_xlsb, sheet_name=None, engine="pyxlsb")

# Iterar sobre cada hoja y guardarla en un archivo CSV
for sheet_name, data in df_dict.items():
    # Guardar la hoja en un CSV con formato seguro
    data.to_csv(
        f"{sheet_name}.csv",
        index=False,  # No incluir índices
        encoding="utf-8",
        sep=";",  # Usar punto y coma como separador
        quotechar='"',  # Poner comillas dobles en cada campo
        na_rep="",  # Evitar que NaN se guarden como 'nan'
    )
    print(f"✅ Hoja '{sheet_name}' guardada como '{sheet_name}.csv'")

print("🎉 Conversión completada")
