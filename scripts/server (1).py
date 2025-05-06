from flask import Flask, render_template, request, jsonify, redirect, url_for
from flask_cors import CORS
import mysql.connector
from dateutil import parser
from datetime import datetime
import pytz
from flask_mail import Mail, Message
from flask import render_template
from flask_cors import cross_origin




app = Flask(__name__, template_folder='app/templates')
CORS(app, supports_credentials=True, origins=["http://192.168.1.49:3000", "http://localhost:3000"])
mail = Mail(app)

# Conexión a MySQL (Railway)
conn = mysql.connector.connect(
    host='tramway.proxy.rlwy.net',
    port=25147,
    user='root',
    password='BTPUnqESBxknaKJSkHHGxNLsvtDQWUlZ',
    database='railway'
)
cursor = conn.cursor(dictionary=True , buffered=True)

# Página de login (HTML)
@app.route('/')
def login_page():
    return render_template('login-conductor.html')

# Página principal luego del login
@app.route('/conductores.html')
def principal():
    # ⚠️ Aquí estamos usando un parámetro por GET (puede venir desde el login o desde la redirección)
    licencia = request.args.get('licencia')

    if not licencia:
        return "⚠️ No se proporcionó una licencia", 400

    cursor.execute("""
        SELECT c.nombre_apellidos AS nombre, c.dni, c.licencia
        FROM conductores c
        WHERE c.licencia = %s
    """, (licencia,))
    
    conductor = cursor.fetchone()

    if not conductor:
        return "❌ Conductor no encontrado", 404

    # 👇 Ahora sí pasamos los datos a la plantilla
    return render_template('conductores.html', 
                           nombre=conductor['nombre'], 
                           licencia=conductor['licencia'], 
                           dni=conductor['dni'])
    
    
    
    
@app.route('/login', methods=['POST'])
@cross_origin(origins=["http://192.168.1.49:3000", "http://localhost:3000"], supports_credentials=True)
def login():
    data = request.get_json()
    email = data.get('email')
    dni = data.get('dni')

    if not email or not dni:
        return jsonify({'message': 'Faltan datos'}), 400

    try:
        cursor.execute("""
            SELECT c.nombre_apellidos AS nombre, c.licencia, c.dni, c.email, 
                   c.numero_seguridad_social, l.marca_modelo AS vehiculo_modelo, 
                   l.nombre_apellidos AS empresa, l.matricula
            FROM conductores c
            JOIN licencias l ON c.licencia = l.licencia
            WHERE c.email = %s AND c.dni = %s
        """, (email, dni))

        usuario = cursor.fetchone()

        if not usuario:
            return jsonify({'message': '❌ Usuario no encontrado'}), 401

        usuario['token'] = 'token_de_ejemplo'  # Token ficticio
        return jsonify(usuario), 200

    except Exception as e:
        print(f"❌ Error en /login:", e)
        return jsonify({'message': 'Error interno del servidor'}), 500


# Registro de eventos API
@app.route('/api/registrar-fecha', methods=['POST'])
def registrar_fecha():
    data = request.get_json()
    print("📥 Datos recibidos:", data)

    accion = data.get('accion')
    licencia = data.get('licencia')
    fecha_utc = parser.parse(data.get("fecha_hora"))  # viene en UTC

    zona_madrid = pytz.timezone("Europe/Madrid")
    fecha_local = fecha_utc.astimezone(zona_madrid)
    fecha_str = fecha_local.strftime("%Y-%m-%d %H:%M:%S")
    fecha_dia = fecha_local.date()  # solo la fecha: 2025-04-10

    if not licencia or not accion:
        return jsonify({'message': 'Faltan datos (licencia o acción)'}), 400

    try:
        # Verificar si ya se registró ese tipo de evento hoy
        if accion in ['inicio_jornada', 'fin_jornada']:
            cursor.execute("""
                SELECT COUNT(*) AS total FROM eventos
                WHERE licencia = %s AND evento = %s AND DATE(fecha_hora) = %s
            """, (licencia, accion, fecha_dia))

            existe = cursor.fetchone()["total"]
            if existe > 0:
                return jsonify({
                    'message': f"⚠️ Ya registraste '{accion.replace('_', ' ')}' hoy."
                }), 400

        # Validación: 'inicio_descanso' requiere 'inicio_jornada' previo
        if accion == "inicio_descanso":
            cursor.execute("""
                SELECT COUNT(*) AS total FROM eventos
                WHERE licencia = %s AND evento = 'inicio_jornada' AND DATE(fecha_hora) = %s
            """, (licencia, fecha_dia))

            jornada_iniciada = cursor.fetchone()["total"]
            if jornada_iniciada == 0:
                return jsonify({
                    'message': "⛔ No puedes iniciar un descanso sin haber iniciado la jornada."
                }), 400

        # Validación: 'fin_descanso' requiere 'inicio_descanso' previo
        if accion == "fin_descanso":
            cursor.execute("""
                SELECT COUNT(*) AS total FROM eventos
                WHERE licencia = %s AND evento = 'inicio_descanso' AND DATE(fecha_hora) = %s
            """, (licencia, fecha_dia))

            descanso_iniciado = cursor.fetchone()["total"]
            if descanso_iniciado == 0:
                return jsonify({
                    'message': "⛔ No puedes finalizar un descanso sin haberlo iniciado."
                }), 400

        # Validación: 'fin_jornada' requiere 'fin_descanso' previo
        if accion == "fin_jornada":
            cursor.execute("""
                SELECT COUNT(*) AS total FROM eventos
                WHERE licencia = %s AND evento = 'fin_descanso' AND DATE(fecha_hora) = %s
            """, (licencia, fecha_dia))

            descanso_finalizado = cursor.fetchone()["total"]
            if descanso_finalizado == 0:
                return jsonify({
                    'message': "⛔ No puedes finalizar la jornada sin haber finalizado el descanso."
                }), 400

        # Buscar datos del conductor
        cursor.execute("""
            SELECT c.nombre_apellidos AS nombre_conductor, c.dni, c.licencia, 
                   l.marca_modelo AS vehiculo_modelo, l.matricula, 
                   c.email, c.numero_seguridad_social AS num_seguridad_social, 
                   l.nombre_apellidos AS empresa
            FROM conductores c
            JOIN licencias l ON c.licencia = l.licencia
            WHERE c.licencia = %s
        """, (licencia,))
        
        conductor = cursor.fetchone()

        if not conductor:
            return jsonify({'message': 'Conductor no encontrado'}), 404

        # Insertar evento
        cursor.execute("""
            INSERT INTO eventos 
            (nombre_conductor, dni, licencia, vehiculo_modelo, matricula, email, 
             num_seguridad_social, empresa, evento, fecha_hora)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        """, (
            conductor['nombre_conductor'],
            conductor['dni'],
            conductor['licencia'],
            conductor['vehiculo_modelo'],
            conductor['matricula'],
            conductor['email'],
            conductor['num_seguridad_social'],
            conductor['empresa'],
            accion,
            fecha_str
        ))
        conn.commit()

        print(f"✅ Evento '{accion}' registrado con éxito.")
        return jsonify({'message': f'✅ Evento \"{accion}\" registrado a las {fecha_str}'}), 200

    except Exception as e:
        print(f"❌ Error en /api/registrar-fecha: {e}")
        return jsonify({'message': 'Error interno del servidor'}), 500
 
    
    
    
# Página de historial (HTML)
@app.route('/historial')
def historial_page():
   
    return render_template('historial.html')   
 
@app.route('/api/eventos/<licencia>', methods=['GET'])
def obtener_eventos_por_licencia(licencia):
    try:
        cursor.execute("""
            SELECT nombre_conductor, dni, licencia, vehiculo_modelo, matricula, email, 
                   num_seguridad_social, empresa, evento, fecha_hora
            FROM eventos
            WHERE licencia = %s
            ORDER BY fecha_hora DESC
            LIMIT 50
        """, (licencia,))
        
        eventos = cursor.fetchall()
        return jsonify(eventos), 200

    except Exception as e:
        print(f"❌ Error al obtener eventos por licencia:", e)
        return jsonify({'message': 'Error al obtener eventos'}), 500


@app.route('/api/send-email', methods=['POST'])
def enviar_correo():
    data = request.json
    email = data['email']  # Este viene del localStorage vía JS
    evento = data.get('evento', 'Evento no especificado')

    contenido = f"Hola, se ha registrado un nuevo evento: {evento}"

    msg = Message(
        "Notificación de evento",
        sender="tucorreo@gmail.com",
        recipients=[email]
    )
    msg.body = contenido

    mail.send(msg)
    return {'status': 'Correo enviado'}

    
    
if __name__ == '__main__':
    app.run(host= "0.0.0.0", port=3000, debug=True)
