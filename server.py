#!/usr/bin/env python3
"""
SERVIDOR DE CLASES DE INGLÉS
Versión profesional para Render.com
Con PostgreSQL y Cloudinary
"""

import os
import psycopg2
import json
import hashlib
import secrets
import jwt
import datetime
from psycopg2.extras import RealDictCursor
from typing import Dict, Optional
from functools import wraps

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import cloudinary
import cloudinary.uploader

# ============ CONFIGURACIÓN ============
app = Flask(__name__, static_folder='.', static_url_path='')
CORS(app, resources={r"/*": {"origins": "*"}})

# Configuración de Render
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB

# PostgreSQL de Render (tu base de datos real)
DATABASE_URL = "postgresql://englishcourse_user:VI8pYTtX2bbv2YftidVHOUKXtK6J7ehd@dpg-d64mmungi27c73b53hr0-a/englishcourse"

# Configuración de Cloudinary (tus credenciales)
cloudinary.config(
    cloud_name="dj72b0ykc",
    api_key="215156196366932",
    api_secret="Ivdpe_mkT3rSx5asFTo6qJdWaLQ",
    secure=True
)

# Códigos de acceso
STUDENT_CODE = "QwErTy89"
TEACHER_CODE = "MOISÉS5M"

# Extensiones permitidas
ALLOWED_EXTENSIONS = {
    'pdf', 'doc', 'docx', 'ppt', 'pptx', 
    'txt', 'jpg', 'jpeg', 'png', 'mp3', 'mp4'
}

# SocketIO SIN async_mode especificado (usa automático)
socketio = SocketIO(app, cors_allowed_origins="*")

# ============ FUNCIONES AUXILIARES ============
def allowed_file(filename: str) -> bool:
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_file_type(filename: str) -> str:
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    file_types = {
        'pdf': 'PDF', 'doc': 'Word', 'docx': 'Word',
        'ppt': 'PowerPoint', 'pptx': 'PowerPoint',
        'txt': 'Texto', 'jpg': 'Imagen', 'jpeg': 'Imagen',
        'png': 'Imagen', 'mp3': 'Audio', 'mp4': 'Video'
    }
    return file_types.get(ext, 'Archivo')

def get_db_connection():
    """Obtener conexión a PostgreSQL"""
    conn = psycopg2.connect(DATABASE_URL, cursor_factory=RealDictCursor)
    return conn

def init_db():
    """Inicializar la base de datos con PostgreSQL"""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Tabla de usuarios
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                name VARCHAR(200) NOT NULL,
                role VARCHAR(20) NOT NULL CHECK(role IN ('student', 'teacher')),
                level VARCHAR(50) DEFAULT 'Sin asignar',
                registration_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            )
        ''')
        
        # Tabla de clases
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS classes (
                id SERIAL PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                description TEXT NOT NULL,
                level VARCHAR(10) NOT NULL CHECK(level IN ('A1', 'A2', 'B1')),
                file_name VARCHAR(255) NOT NULL,
                file_url TEXT NOT NULL,
                file_type VARCHAR(50) NOT NULL,
                file_size INTEGER NOT NULL,
                uploaded_by INTEGER NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (uploaded_by) REFERENCES users (id) ON DELETE CASCADE
            )
        ''')
        
        # Tabla de descargas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS downloads (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL,
                class_id INTEGER NOT NULL,
                downloaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE,
                FOREIGN KEY (class_id) REFERENCES classes (id) ON DELETE CASCADE
            )
        ''')
        
        conn.commit()
        print("✅ Tablas creadas exitosamente")
        
    except Exception as e:
        print(f"⚠️  Error al crear tablas: {str(e)}")
        conn.rollback()
    finally:
        cursor.close()
        conn.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def verify_password(password: str, password_hash: str) -> bool:
    return hash_password(password) == password_hash

def generate_token(user_id: int, username: str, role: str) -> str:
    payload = {
        'user_id': user_id,
        'username': username,
        'role': role,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(days=7)
    }
    return jwt.encode(payload, app.config['SECRET_KEY'], algorithm='HS256')

def verify_token(token: str) -> Optional[Dict]:
    try:
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        return payload
    except:
        return None

# ============ DECORADORES ============
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(' ')[1]
        
        if not token:
            return jsonify({'error': 'Token de autenticación requerido'}), 401
        
        payload = verify_token(token)
        if not payload:
            return jsonify({'error': 'Token inválido o expirado'}), 401
        
        request.user_id = payload['user_id']
        request.username = payload['username']
        request.user_role = payload['role']
        
        return f(*args, **kwargs)
    return decorated

def teacher_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not hasattr(request, 'user_role') or request.user_role != 'teacher':
            return jsonify({'error': 'Acceso denegado. Solo para profesores'}), 403
        return f(*args, **kwargs)
    return decorated

# ============ RUTAS API ============
@app.route('/')
def index():
    return send_file('auth.html')

@app.route('/api/register', methods=['POST'])
def register():
    """Registrar un nuevo usuario"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'Datos JSON inválidos'}), 400
        
        required_fields = ['name', 'username', 'password', 'code']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Campo {field} es requerido'}), 400
        
        code = data['code']
        if code not in [STUDENT_CODE, TEACHER_CODE]:
            return jsonify({'error': 'Código de acceso incorrecto'}), 400
        
        role = 'teacher' if code == TEACHER_CODE else 'student'
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar si usuario existe
        cursor.execute('SELECT id FROM users WHERE username = %s', (data['username'],))
        if cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'El nombre de usuario ya existe'}), 400
        
        # Crear usuario
        password_hash = hash_password(data['password'])
        
        cursor.execute('''
            INSERT INTO users (username, password_hash, name, role, level)
            VALUES (%s, %s, %s, %s, %s) RETURNING id, username, name, role, level, registration_date
        ''', (
            data['username'],
            password_hash,
            data['name'],
            role,
            'Sin asignar' if role == 'student' else None
        ))
        
        user = cursor.fetchone()
        conn.commit()
        
        # Generar token
        token = generate_token(user['id'], user['username'], user['role'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Usuario registrado exitosamente',
            'user': dict(user),
            'token': token
        }), 201
        
    except Exception as e:
        print(f"❌ Error en registro: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/login', methods=['POST'])
def login():
    """Iniciar sesión"""
    try:
        data = request.get_json()
        
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Usuario y contraseña son requeridos'}), 400
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE username = %s', (data['username'],))
        user_row = cursor.fetchone()
        
        if not user_row:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401
        
        user = dict(user_row)
        
        if not verify_password(data['password'], user['password_hash']):
            cursor.close()
            conn.close()
            return jsonify({'error': 'Usuario o contraseña incorrectos'}), 401
        
        # Actualizar último login
        cursor.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = %s', (user['id'],))
        conn.commit()
        
        # Eliminar información sensible
        del user['password_hash']
        
        # Generar token
        token = generate_token(user['id'], user['username'], user['role'])
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Login exitoso',
            'user': user,
            'token': token
        }), 200
        
    except Exception as e:
        print(f"❌ Error en login: {str(e)}")
        return jsonify({'error': 'Error interno del servidor'}), 500

@app.route('/api/classes', methods=['GET'])
@token_required
def get_classes():
    """Obtener clases con filtro"""
    try:
        level = request.args.get('level', 'A1')
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if level in ['A1', 'A2', 'B1']:
            cursor.execute('''
                SELECT c.*, u.name as uploaded_by_name 
                FROM classes c 
                JOIN users u ON c.uploaded_by = u.id 
                WHERE c.level = %s 
                ORDER BY c.created_at DESC
            ''', (level,))
        else:
            cursor.execute('''
                SELECT c.*, u.name as uploaded_by_name 
                FROM classes c 
                JOIN users u ON c.uploaded_by = u.id 
                ORDER BY c.created_at DESC
            ''')
        
        classes = []
        for row in cursor.fetchall():
            class_dict = dict(row)
            classes.append(class_dict)
        
        cursor.close()
        conn.close()
        
        return jsonify(classes), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo clases: {str(e)}")
        return jsonify({'error': 'Error obteniendo clases'}), 500

@app.route('/api/classes/all', methods=['GET'])
@token_required
@teacher_required
def get_all_classes():
    """Obtener todas las clases (solo para profesores)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT c.*, u.name as uploaded_by_name 
            FROM classes c 
            JOIN users u ON c.uploaded_by = u.id 
            ORDER BY c.created_at DESC
        ''')
        
        classes = []
        for row in cursor.fetchall():
            classes.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(classes), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo todas las clases: {str(e)}")
        return jsonify({'error': 'Error obteniendo clases'}), 500

@app.route('/api/classes/<int:class_id>', methods=['GET'])
@token_required
def get_class(class_id: int):
    """Obtener una clase específica"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT c.*, u.name as uploaded_by_name 
            FROM classes c 
            JOIN users u ON c.uploaded_by = u.id 
            WHERE c.id = %s
        ''', (class_id,))
        
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        cursor.close()
        conn.close()
        
        return jsonify(dict(class_data)), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo clase: {str(e)}")
        return jsonify({'error': 'Error obteniendo clase'}), 500

@app.route('/api/classes', methods=['POST'])
@token_required
@teacher_required
def upload_class():
    """Subir nueva clase a Cloudinary"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'error': 'No se seleccionó ningún archivo'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Tipo de archivo no permitido'}), 400
        
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        level = request.form.get('level', '').strip()
        
        if not title or not description or not level:
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if level not in ['A1', 'A2', 'B1']:
            return jsonify({'error': 'Nivel no válido'}), 400
        
        # Subir a Cloudinary
        upload_result = cloudinary.uploader.upload(
            file,
            folder="clases_ingles",
            resource_type="auto",
            use_filename=True,
            unique_filename=True
        )
        
        # Guardar en PostgreSQL
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO classes 
            (title, description, level, file_name, file_url, file_type, file_size, uploaded_by)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id, title, description, level, file_name, file_url, file_type, created_at
        ''', (
            title,
            description,
            level,
            secure_filename(file.filename),
            upload_result['secure_url'],
            get_file_type(file.filename),
            upload_result.get('bytes', 0),
            request.user_id
        ))
        
        new_class = cursor.fetchone()
        conn.commit()
        
        cursor.close()
        conn.close()
        
        # Notificar por WebSocket
        socketio.emit('new_class', dict(new_class))
        
        return jsonify({
            'message': 'Clase subida exitosamente',
            'class': dict(new_class)
        }), 201
        
    except Exception as e:
        print(f"❌ Error subiendo clase: {str(e)}")
        return jsonify({'error': 'Error subiendo la clase'}), 500

@app.route('/api/classes/<int:class_id>', methods=['PUT'])
@token_required
@teacher_required
def update_class(class_id: int):
    """Actualizar una clase existente"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que la clase existe y pertenece al profesor
        cursor.execute('SELECT * FROM classes WHERE id = %s', (class_id,))
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        # Obtener datos del formulario
        title = request.form.get('title', '').strip()
        description = request.form.get('description', '').strip()
        level = request.form.get('level', '').strip()
        file = request.files.get('file')
        
        if not title or not description or not level:
            return jsonify({'error': 'Todos los campos son requeridos'}), 400
        
        if level not in ['A1', 'A2', 'B1']:
            return jsonify({'error': 'Nivel no válido'}), 400
        
        update_fields = {
            'title': title,
            'description': description,
            'level': level
        }
        
        file_url = class_data['file_url']
        file_name = class_data['file_name']
        file_type = class_data['file_type']
        file_size = class_data['file_size']
        
        # Si se subió un nuevo archivo
        if file and file.filename != '':
            if not allowed_file(file.filename):
                return jsonify({'error': 'Tipo de archivo no permitido'}), 400
            
            # Subir nuevo archivo a Cloudinary
            upload_result = cloudinary.uploader.upload(
                file,
                folder="clases_ingles",
                resource_type="auto",
                use_filename=True,
                unique_filename=True
            )
            
            file_url = upload_result['secure_url']
            file_name = secure_filename(file.filename)
            file_type = get_file_type(file.filename)
            file_size = upload_result.get('bytes', 0)
            
            update_fields.update({
                'file_url': file_url,
                'file_name': file_name,
                'file_type': file_type,
                'file_size': file_size
            })
        
        # Actualizar en la base de datos
        set_clause = ', '.join([f"{k} = %s" for k in update_fields.keys()])
        values = list(update_fields.values())
        values.append(class_id)
        
        cursor.execute(f'''
            UPDATE classes 
            SET {set_clause}, created_at = created_at
            WHERE id = %s
            RETURNING id, title, description, level, file_name, file_url, file_type, created_at
        ''', values)
        
        updated_class = cursor.fetchone()
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Clase actualizada exitosamente',
            'class': dict(updated_class)
        }), 200
        
    except Exception as e:
        print(f"❌ Error actualizando clase: {str(e)}")
        return jsonify({'error': 'Error actualizando la clase'}), 500

@app.route('/api/classes/<int:class_id>', methods=['DELETE'])
@token_required
@teacher_required
def delete_class(class_id: int):
    """Eliminar una clase"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que la clase existe
        cursor.execute('SELECT * FROM classes WHERE id = %s', (class_id,))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        # Eliminar la clase
        cursor.execute('DELETE FROM classes WHERE id = %s', (class_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Clase eliminada exitosamente'}), 200
        
    except Exception as e:
        print(f"❌ Error eliminando clase: {str(e)}")
        return jsonify({'error': 'Error eliminando la clase'}), 500

@app.route('/api/classes/<int:class_id>/download', methods=['GET'])
@token_required
def download_class(class_id: int):
    """Registrar descarga (redirige a Cloudinary)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM classes WHERE id = %s', (class_id,))
        class_data = cursor.fetchone()
        
        if not class_data:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Clase no encontrada'}), 404
        
        # Registrar descarga
        cursor.execute('''
            INSERT INTO downloads (user_id, class_id) 
            VALUES (%s, %s)
        ''', (request.user_id, class_id))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Redirigiendo a descarga',
            'download_url': class_data['file_url']
        }), 200
        
    except Exception as e:
        print(f"❌ Error en descarga: {str(e)}")
        return jsonify({'error': 'Error en la descarga'}), 500

@app.route('/api/students', methods=['GET'])
@token_required
@teacher_required
def get_students():
    """Obtener todos los estudiantes (solo para profesores)"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, name, role, level, registration_date, last_login
            FROM users 
            WHERE role = 'student'
            ORDER BY name
        ''')
        
        students = []
        for row in cursor.fetchall():
            students.append(dict(row))
        
        cursor.close()
        conn.close()
        
        return jsonify(students), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo estudiantes: {str(e)}")
        return jsonify({'error': 'Error obteniendo estudiantes'}), 500

@app.route('/api/students/<int:student_id>/level', methods=['PUT'])
@token_required
@teacher_required
def update_student_level(student_id: int):
    """Actualizar el nivel de un estudiante"""
    try:
        data = request.get_json()
        
        if not data or 'level' not in data:
            return jsonify({'error': 'Nivel es requerido'}), 400
        
        level = data['level'].strip()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que el estudiante existe
        cursor.execute('SELECT id FROM users WHERE id = %s AND role = %s', 
                      (student_id, 'student'))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Estudiante no encontrado'}), 404
        
        # Actualizar nivel
        cursor.execute('''
            UPDATE users 
            SET level = %s 
            WHERE id = %s
            RETURNING id, username, name, role, level
        ''', (level, student_id))
        
        updated_student = cursor.fetchone()
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({
            'message': 'Nivel actualizado exitosamente',
            'student': dict(updated_student)
        }), 200
        
    except Exception as e:
        print(f"❌ Error actualizando nivel: {str(e)}")
        return jsonify({'error': 'Error actualizando el nivel'}), 500

@app.route('/api/students/<int:student_id>', methods=['DELETE'])
@token_required
@teacher_required
def delete_student(student_id: int):
    """Eliminar un estudiante"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Verificar que el estudiante existe
        cursor.execute('SELECT id FROM users WHERE id = %s AND role = %s', 
                      (student_id, 'student'))
        if not cursor.fetchone():
            cursor.close()
            conn.close()
            return jsonify({'error': 'Estudiante no encontrado'}), 404
        
        # Eliminar el estudiante
        cursor.execute('DELETE FROM users WHERE id = %s', (student_id,))
        conn.commit()
        
        cursor.close()
        conn.close()
        
        return jsonify({'message': 'Estudiante eliminado exitosamente'}), 200
        
    except Exception as e:
        print(f"❌ Error eliminando estudiante: {str(e)}")
        return jsonify({'error': 'Error eliminando el estudiante'}), 500

@app.route('/api/profile', methods=['GET'])
@token_required
def get_profile():
    """Obtener perfil del usuario"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, username, name, role, level, registration_date, last_login
            FROM users WHERE id = %s
        ''', (request.user_id,))
        
        user = cursor.fetchone()
        
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'error': 'Usuario no encontrado'}), 404
        
        # Estadísticas
        if request.user_role == 'student':
            cursor.execute('SELECT COUNT(*) FROM downloads WHERE user_id = %s', (request.user_id,))
        else:
            cursor.execute('SELECT COUNT(*) FROM classes WHERE uploaded_by = %s', (request.user_id,))
            cursor.execute('SELECT COUNT(*) FROM users WHERE role = %s', ('student',))
        
        stats = {'classes_count': cursor.fetchone()['count']}
        
        if request.user_role == 'teacher':
            students_count = cursor.fetchone()['count']
            stats['students_count'] = students_count
        
        cursor.close()
        conn.close()
        
        profile = dict(user)
        profile['stats'] = stats
        
        return jsonify(profile), 200
        
    except Exception as e:
        print(f"❌ Error obteniendo perfil: {str(e)}")
        return jsonify({'error': 'Error obteniendo perfil'}), 500

# ============ SERVIR ARCHIVOS ESTÁTICOS ============
@app.route('/<path:path>')
def serve_static(path):
    try:
        return send_from_directory('.', path)
    except:
        return jsonify({'error': 'Archivo no encontrado'}), 404

# ============ MANEJADORES WEBSOCKET ============
@socketio.on('connect')
def handle_connect():
    emit('connection_response', {'message': 'Conectado'})

@socketio.on('disconnect')
def handle_disconnect():
    pass

# ============ INICIALIZACIÓN ============
if __name__ == '__main__':
    # Inicializar base de datos
    print("=" * 60)
    print("🚀 INICIANDO SERVIDOR DE CLASES DE INGLÉS")
    print("=" * 60)
    print("🔧 Configurando base de datos PostgreSQL...")
    
    try:
        init_db()
        print("✅ Base de datos configurada exitosamente")
        print(f"🔑 Código estudiante: {STUDENT_CODE}")
        print(f"👨‍🏫 Código profesor: {TEACHER_CODE}")
        print("=" * 60)
    except Exception as e:
        print(f"⚠️  Error configurando base de datos: {str(e)}")
        print("ℹ️  Continuando... (las tablas pueden ya existir)")
    
    port = int(os.environ.get('PORT', 5000))
    
    # Para producción en Render
    socketio.run(
        app, 
        host='0.0.0.0', 
        port=port, 
        debug=False,
        allow_unsafe_werkzeug=True
    )