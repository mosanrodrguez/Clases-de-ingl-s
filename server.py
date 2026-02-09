#!/usr/bin/env python3
"""
Servidor para la plataforma de Clases de Inglés
Con SQLite, WebSocket y autenticación JWT
"""

import os
import sqlite3
import json
import hashlib
import secrets
import jwt
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from functools import wraps

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit, join_room, leave_room

# Configuración
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app)
app.config['SECRET_KEY'] = secrets.token_hex(32)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['DATABASE'] = 'english_classes.db'
app.config['JWT_SECRET'] = secrets.token_hex(32)
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_EXPIRATION'] = 86400  # 24 horas

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Crear directorios necesarios
Path(app.config['UPLOAD_FOLDER']).mkdir(exist_ok=True)

# Códigos de acceso
STUDENT_CODE = "QwErTy89"
TEACHER_CODE = "MOISÉS5M"

# Extensiónes permitidas
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 
    'txt', 'jpg', 'jpeg', 'png', 'mp3', 'mp4'
}

def allowed_file(filename: str) -> bool:
    """Verificar si la extensión del archivo está permitida"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename: str) -> str:
    """Obtener el tipo de archivo para mostrar"""
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    file_types = {
        'pdf': 'PDF',
        'doc': 'Word',
        'docx': 'Word',
        'ppt': 'PowerPoint',
        'pptx': 'PowerPoint',
        'txt': 'Texto',
        'jpg': 'Imagen',
        'jpeg': 'Imagen',
        'png': 'Imagen',
        'mp3': 'Audio',
        'mp4': 'Video'
    }
    return file_types.get(ext, 'Archivo')

def get_db_connection():
    """Obtener conexión a la base de datos"""
    conn = sqlite3.connect(app.config['DATABASE'])
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Inicializar la base de datos con tablas necesarias"""
    conn = get_db_connection()
    
    # Tabla de usuarios
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('student', 'teacher')),
            level TEXT,
            registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')
    
    # Tabla de clases
    conn.execute('''
        CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            level TEXT NOT NULL CHECK(level IN ('A1', 'A2', 'B1')),
            file_name TEXT NOT NULL,
            file_path TEXT NOT NULL,
            file_type TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            uploaded_by INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (uploaded_by) REFERENCES users (id)
        )
    ''')
    
    # Tabla de descargas
    conn.execute('''
        CREATE TABLE IF NOT EXISTS downloads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            class_id INTEGER NOT NULL,
            downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id),
            FOREIGN KEY (class_id) REFERENCES classes (id)
        )
    ''')
    
    # Crear usuario profesor si no existe
    cursor = conn.execute('SELECT * FROM users WHERE role = ?', ('teacher',))
    if not cursor.fetchone():
        password_hash = hashlib.sha256('admin123'.encode()).hexdigest()
        conn.execute('''
            INSERT INTO users (username, password_hash, name, role)
            VALUES (?, ?, ?, ?)
        ''', ('profesor', password_hash, 'Profesor Moisés', 'teacher'))
        print("✓ Usuario profesor creado: profesor / admin123")
    
    conn.commit()
    conn.close()

def hash_password(password: str) -> str:
    """Hashear una contraseña"""
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    """Verificar una contraseña"""
    return hash_password(password) == password_hash

def generate_token(user_id: int, username: str, role: str) -> str:
    """Generar token JWT"""
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=app.config['JWT_EXPIRATION'])
    }
    return jwt.encode(payload, app.config['JWT_SECRET'], algorithm=app.config['JWT_ALGORITHM'])

def verify_token(token: str) -> Optional[Dict]:
    """Verificar y decodificar token JWT"""
    try:
        payload = jwt.decode(token, app.config['JWT_SECRET'], algorithms=[app.config['JWT_ALGORITHM']])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def token_required(f):
    """Decorador para requerir token JWT"""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Obtener token del header Authorization
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token de autenticación requerido'}), 401
        
        # Verificar token
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token inválido o expirado'}), 401
        
        # Agregar información del usuario al request
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated

def teacher_required(f):
    """Decorador para requerir rol de profesor"""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user_role') or request.user_role != 'teacher':
            return jsonify({'error': 'Acceso denegado. Solo para profesores'}), 403
        return f(*args, **kwargs)
    return decorated

# Rutas de la API
@app.route('/')
def index():
    """Página principal - redirige a auth.html"""
    return send_file('auth.html')

@app.route('/api/register', methods=['POST'])
def register():
    """Registrar un nuevo usuario"""
    data = request.get_json()
    
    # Validar campos requeridos
    required_fields = ['name', 'username', 'password', 'code']
    for field in required_fields:
        if not data.get(field):
            return jsonify({'error': f'Campo {field} es requerido'}), 400
    
    # Validar código
    code = data['code']
    if code not in [STUDENT_CODE, TEACHER_CODE]:
        return jsonify({'error': 'Código de acceso incorrecto'}), 400
    
    # Determinar rol basado en el código
    role = 'teacher' if code == TEACHER_CODE else 'student'
    
    # Verificar si el usuario ya existe
    conn = get_db_connection()
    cursor = conn.execute('SELECT id FROM users WHERE username = ?', (data['username'],))
    if cursor.fetchone():
        conn.close()
        return jsonify({'error': 'El nombre de usuario ya existe', 'field': 'registerUsername'}), 400
    
    # Crear usuario
    password_hash = hash_password(data['password'])
    
    conn.execute('''
        INSERT INTO users (username, password_hash, name, role, level)
        VALUES (?, ?, ?, ?, ?)
    ''', (
        data['username'],
        password_hash,
        data['name'],
        role,
        'Sin asignar' if role == 'student' else None
    ))
    
    user_id = conn.lastrowid
    conn.commit()
    
    # Obtener información del usuario creado
    cursor = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    user = dict(cursor.fetchone())
    conn.close()
    
    # Eliminar información sensible
    del user['password_hash']
    
    # Generar token
    token = generate_token(user['id'], user['username'], user['role'])
    
    return jsonify({
        'message': 'Usuario registrado exitosamente',
        'user': user,
        'token': token
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    """Iniciar sesión"""
    data = request.get_json()
    
    if not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400
    
    # Buscar usuario
    conn = get_db_connection()
    cursor = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],))
    user_row = cursor.fetchone()
    
    if not user_row:
        conn.close()
        return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401
    
    user = dict(user_row)
    
    # Verificar contraseña
    if not verify_password(data['password'], user['password_hash']):
        conn.close()
        return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401
    
    # Actualizar último login
    conn.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
    conn.commit()
    conn.close()
    
    # Eliminar información sensible
    del user['password_hash']
    
    # Generar token
    token = generate_token(user['id'], user['username'], user['role'])
    
    return jsonify({
        'message': 'Login exitoso',
        'user': user,
        'token': token
    }), 200

@app.route('/api/classes', methods=['GET'])
@token_required
def get_classes():
    """Obtener lista de clases (con filtro por nivel)"""
    level = request.args.get('level', 'A1')
    
    conn = get_db_connection()
    
    if level in ['A1', 'A2', 'B1']:
        cursor = conn.execute('''
            SELECT c.*, u.name as uploaded_by_name 
            FROM classes c 
            JOIN users u ON c.uploaded_by = u.id 
            WHERE c.level = ? 
            ORDER BY c.created_at DESC
        ''', (level,))
    else:
        cursor = conn.execute('''
            SELECT c.*, u.name as uploaded_by_name 
            FROM classes c 
            JOIN users u ON c.uploaded_by = u.id 
            ORDER BY c.created_at DESC
        ''')
    
    classes = []
    for row in cursor.fetchall():
        class_dict = dict(row)
        
        # Convertir fecha a string ISO
        if class_dict['created_at']:
            try:
                class_dict['created_at'] = datetime.datetime.strptime(
                    class_dict['created_at'], '%Y-%m-%d %H:%M:%S'
                ).isoformat()
            except:
                class_dict['created_at'] = class_dict['created_at']
        
        classes.append(class_dict)
    
    conn.close()
    return jsonify(classes), 200

@app.route('/api/classes', methods=['POST'])
@token_required
@teacher_required
def upload_class():
    """Subir una nueva clase (solo profesor)"""
    # Verificar si hay archivo
    if 'file' not in request.files:
        return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Tipo de archivo no permitido'}), 400
    
    # Obtener datos del formulario
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    level = request.form.get('level', '').strip()
    
    if not title or not description or not level:
        return jsonify({'error': 'Todos los campos son requeridos'}), 400
    
    if level not in ['A1', 'A2', 'B1']:
        return jsonify({'error': 'Nivel no válido'}), 400
    
    # Guardar archivo
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    
    # Asegurar nombre único
    counter = 1
    while os.path.exists(file_path):
        name, ext = os.path.splitext(filename)
        filename = f"{name}_{counter}{ext}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        counter += 1
    
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    
    # Guardar en base de datos
    conn = get_db_connection()
    conn.execute('''
        INSERT INTO classes 
        (title, description, level, file_name, file_path, file_type, file_size, uploaded_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        title,
        description,
        level,
        filename,
        file_path,
        get_file_type(filename),
        file_size,
        request.user_id
    ))
    
    class_id = conn.lastrowid
    
    # Obtener información de la clase creada
    cursor = conn.execute('''
        SELECT c.*, u.name as uploaded_by_name 
        FROM classes c 
        JOIN users u ON c.uploaded_by = u.id 
        WHERE c.id = ?
    ''', (class_id,))
    
    new_class = dict(cursor.fetchone())
    
    # Convertir fecha a string ISO
    if new_class['created_at']:
        try:
            new_class['created_at'] = datetime.datetime.strptime(
                new_class['created_at'], '%Y-%m-%d %H:%M:%S'
            ).isoformat()
        except:
            new_class['created_at'] = new_class['created_at']
    
    conn.commit()
    conn.close()
    
    # Notificar a través de WebSocket
    socketio.emit('new_class', new_class, namespace='/classes', broadcast=True)
    
    return jsonify({
        'message': 'Clase subida exitosamente',
        'class': new_class
    }), 201

@app.route('/api/classes/<int:class_id>/download', methods=['GET'])
@token_required
def download_class(class_id: int):
    """Descargar una clase"""
    conn = get_db_connection()
    
    # Verificar si la clase existe
    cursor = conn.execute('SELECT * FROM classes WHERE id = ?', (class_id,))
    class_row = cursor.fetchone()
    
    if not class_row:
        conn.close()
        return jsonify({'error': 'Clase no encontrada'}), 404
    
    class_data = dict(class_row)
    
    # Verificar que el archivo exista
    if not os.path.exists(class_data['file_path']):
        conn.close()
        return jsonify({'error': 'Archivo no encontrado'}), 404
    
    # Registrar descarga
    conn.execute('''
        INSERT INTO downloads (user_id, class_id) 
        VALUES (?, ?)
    ''', (request.user_id, class_id))
    conn.commit()
    conn.close()
    
    # Enviar archivo
    return send_file(
        class_data['file_path'],
        as_attachment=True,
        download_name=class_data['file_name']
    )

@app.route('/api/stats', methods=['GET'])
@token_required
@teacher_required
def get_stats():
    """Obtener estadísticas (solo profesor)"""
    conn = get_db_connection()
    
    # Estadísticas básicas
    cursor = conn.execute('SELECT COUNT(*) as total FROM users WHERE role = ?', ('student',))
    total_students = cursor.fetchone()['total']
    
    cursor = conn.execute('SELECT COUNT(*) as total FROM classes')
    total_classes = cursor.fetchone()['total']
    
    cursor = conn.execute('SELECT COUNT(*) as total FROM downloads')
    total_downloads = cursor.fetchone()['total']
    
    # Clases por nivel
    cursor = conn.execute('''
        SELECT level, COUNT(*) as count 
        FROM classes 
        GROUP BY level 
        ORDER BY level
    ''')
    classes_by_level = {row['level']: row['count'] for row in cursor.fetchall()}
    
    # Últimas clases
    cursor = conn.execute('''
        SELECT c.title, c.created_at, u.name as uploaded_by, c.level
        FROM classes c
        JOIN users u ON c.uploaded_by = u.id
        ORDER BY c.created_at DESC
        LIMIT 5
    ''')
    recent_classes = [
        {
            'title': row['title'],
            'created_at': row['created_at'],
            'uploaded_by': row['uploaded_by'],
            'level': row['level']
        }
        for row in cursor.fetchall()
    ]
    
    # Top clases descargadas
    cursor = conn.execute('''
        SELECT c.title, COUNT(d.id) as download_count
        FROM downloads d
        JOIN classes c ON d.class_id = c.id
        GROUP BY c.id, c.title
        ORDER BY download_count DESC
        LIMIT 5
    ''')
    top_classes = [
        {
            'title': row['title'],
            'download_count': row['download_count']
        }
        for row in cursor.fetchall()
    ]
    
    conn.close()
    
    return jsonify({
        'total_students': total_students,
        'total_classes': total_classes,
        'total_downloads': total_downloads,
        'classes_by_level': classes_by_level,
        'recent_classes': recent_classes,
        'top_classes': top_classes
    }), 200

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    """Obtener perfil del usuario actual"""
    conn = get_db_connection()
    cursor = conn.execute('''
        SELECT id, username, name, role, level, registration_date, last_login
        FROM users 
        WHERE id = ?
    ''', (request.user_id,))
    
    user = dict(cursor.fetchone())
    conn.close()
    
    # Obtener estadísticas del usuario
    conn = get_db_connection()
    
    if request.user_role == 'student':
        cursor = conn.execute('''
            SELECT COUNT(*) as classes_downloaded
            FROM downloads 
            WHERE user_id = ?
        ''', (request.user_id,))
        stats = dict(cursor.fetchone())
    else:
        cursor = conn.execute('''
            SELECT COUNT(*) as classes_uploaded
            FROM classes 
            WHERE uploaded_by = ?
        ''', (request.user_id,))
        stats = dict(cursor.fetchone())
    
    conn.close()
    
    user['stats'] = stats
    return jsonify(user), 200

# Handlers de WebSocket
@socketio.on('connect', namespace='/classes')
def handle_connect():
    """Manejar conexión WebSocket"""
    print(f'✓ Cliente conectado: {request.sid}')
    emit('connection_response', {'message': 'Conectado al servidor de clases'})

@socketio.on('disconnect', namespace='/classes')
def handle_disconnect():
    """Manejar desconexión WebSocket"""
    print(f'✗ Cliente desconectado: {request.sid}')

@socketio.on('join', namespace='/classes')
def handle_join(data):
    """Unirse a una sala (para notificaciones específicas)"""
    room = data.get('room')
    if room:
        join_room(room)
        print(f'→ Cliente {request.sid} se unió a la sala {room}')
        emit('join_response', {'message': f'Unido a la sala {room}'}, room=room)

@socketio.on('leave', namespace='/classes')
def handle_leave(data):
    """Salir de una sala"""
    room = data.get('room')
    if room:
        leave_room(room)
        print(f'← Cliente {request.sid} salió de la sala {room}')

# Servir archivos estáticos
@app.route('/<path:path>')
def serve_static(path):
    """Servir archivos estáticos"""
    try:
        return send_from_directory('.', path)
    except:
        return jsonify({'error': 'Archivo no encontrado'}), 404

@app.errorhandler(404)
def not_found(error):
    """Manejador de error 404"""
    return jsonify({'error': 'Ruta no encontrada'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Manejador de error 500"""
    return jsonify({'error': 'Error interno del servidor'}), 500

if __name__ == '__main__':
    # Inicializar base de datos
    init_db()
    
    print("=" * 60)
    print("🌟 SERVIDOR DE CLASES DE INGLÉS")
    print("=" * 60)
    print(f"🌐 URL: http://localhost:5000")
    print(f"🔑 Código estudiante: {STUDENT_CODE}")
    print(f"👨‍🏫 Código profesor: {TEACHER_CODE}")
    print(f"📁 Uploads: {app.config['UPLOAD_FOLDER']}/")
    print(f"💾 Base de datos: {app.config['DATABASE']}")
    print("=" * 60)
    print("📂 Archivos necesarios en la carpeta:")
    print("   • auth.html")
    print("   • clases.html")
    print("   • server.py")
    print("=" * 60)
    print("🚀 Servidor iniciado. Presiona Ctrl+C para detener.")
    print("=" * 60)
    
    # Ejecutar servidor
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=5000, 
        debug=True,
        allow_unsafe_werkzeug=True
    )